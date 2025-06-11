package com.figrclub.figrclubdb.service.ratelimit;

import com.figrclub.figrclubdb.domain.model.LoginAttempt;
import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.RateLimitInfo;
import com.figrclub.figrclubdb.enums.AttemptType;
import com.figrclub.figrclubdb.enums.BlockType;
import com.figrclub.figrclubdb.exceptions.RateLimitExceededException;
import com.figrclub.figrclubdb.repository.LoginAttemptRepository;
import com.figrclub.figrclubdb.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class RateLimitingService implements IRateLimitingService {

    private final LoginAttemptRepository loginAttemptRepository;
    private final UserRepository userRepository;

    // Configuración de límites por defecto
    @Value("${app.security.rate-limit.max-attempts-per-ip:10}")
    private int maxAttemptsPerIp;

    @Value("${app.security.rate-limit.max-attempts-per-user:5}")
    private int maxAttemptsPerUser;

    @Value("${app.security.rate-limit.window-minutes:15}")
    private int windowMinutes;

    @Value("${app.security.rate-limit.block-duration-minutes:30}")
    private int blockDurationMinutes;

    @Value("${app.security.rate-limit.progressive-block:true}")
    private boolean progressiveBlock;

    @Override
    @Transactional
    public void recordFailedAttempt(String ipAddress, String email, AttemptType attemptType) {
        log.debug("Recording failed attempt: IP={}, email={}, type={}", ipAddress, email, attemptType);

        LoginAttempt attempt = LoginAttempt.builder()
                .ipAddress(ipAddress)
                .email(email)
                .attemptType(attemptType)
                .success(false)
                .attemptTime(LocalDateTime.now())
                .build();

        loginAttemptRepository.save(attempt);

        // Verificar si se debe bloquear por IP o usuario
        checkAndBlockIfNecessary(ipAddress, email, attemptType);
    }

    @Override
    @Transactional
    public void recordSuccessfulAttempt(String ipAddress, String email, AttemptType attemptType) {
        log.debug("Recording successful attempt: IP={}, email={}, type={}", ipAddress, email, attemptType);

        LoginAttempt attempt = LoginAttempt.builder()
                .ipAddress(ipAddress)
                .email(email)
                .attemptType(attemptType)
                .success(true)
                .attemptTime(LocalDateTime.now())
                .build();

        loginAttemptRepository.save(attempt);

        // Limpiar intentos fallidos anteriores para este usuario/IP
        if (email != null) {
            clearFailedAttemptsForUser(email);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isIpBlocked(String ipAddress) {
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(blockDurationMinutes);

        // Verificar bloqueo explícito por IP
        boolean explicitlyBlocked = loginAttemptRepository.isIpExplicitlyBlocked(ipAddress, windowStart);
        if (explicitlyBlocked) {
            log.debug("IP {} is explicitly blocked", ipAddress);
            return true;
        }

        // Verificar límite de intentos por IP
        LocalDateTime attemptWindowStart = LocalDateTime.now().minusMinutes(windowMinutes);
        long failedAttempts = loginAttemptRepository.countFailedAttemptsByIp(ipAddress, attemptWindowStart);

        boolean rateLimited = failedAttempts >= maxAttemptsPerIp;
        if (rateLimited) {
            log.debug("IP {} exceeded rate limit: {} attempts", ipAddress, failedAttempts);
        }

        return rateLimited;
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isUserBlocked(String email) {
        if (email == null) return false;

        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(blockDurationMinutes);

        // Verificar bloqueo explícito por usuario
        boolean explicitlyBlocked = loginAttemptRepository.isUserExplicitlyBlocked(email, windowStart);
        if (explicitlyBlocked) {
            log.debug("User {} is explicitly blocked", email);
            return true;
        }

        // Verificar límite de intentos por usuario
        LocalDateTime attemptWindowStart = LocalDateTime.now().minusMinutes(windowMinutes);
        long failedAttempts = loginAttemptRepository.countFailedAttemptsByUser(email, attemptWindowStart);

        boolean rateLimited = failedAttempts >= maxAttemptsPerUser;
        if (rateLimited) {
            log.debug("User {} exceeded rate limit: {} attempts", email, failedAttempts);
        }

        return rateLimited;
    }

    @Override
    @Transactional(readOnly = true)
    public void validateRateLimit(String ipAddress, String email, AttemptType attemptType) {
        if (isIpBlocked(ipAddress)) {
            log.warn("Rate limit exceeded for IP: {} attempting {}", ipAddress, attemptType);
            throw new RateLimitExceededException(
                    String.format("Too many attempts from this IP address. Please try again in %d minutes.",
                            blockDurationMinutes),
                    BlockType.IP_BLOCKED,
                    blockDurationMinutes
            );
        }

        if (isUserBlocked(email)) {
            log.warn("Rate limit exceeded for user: {} attempting {}", email, attemptType);
            throw new RateLimitExceededException(
                    String.format("Too many failed attempts for this account. Please try again in %d minutes.",
                            blockDurationMinutes),
                    BlockType.USER_BLOCKED,
                    blockDurationMinutes
            );
        }
    }

    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "rate-limit-info", key = "#ipAddress + '_' + #email")
    public RateLimitInfo getRateLimitInfo(String ipAddress, String email) {
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(windowMinutes);

        long ipAttempts = loginAttemptRepository.countFailedAttemptsByIp(ipAddress, windowStart);
        long userAttempts = email != null ?
                loginAttemptRepository.countFailedAttemptsByUser(email, windowStart) : 0;

        int remainingIpAttempts = Math.max(0, maxAttemptsPerIp - (int)ipAttempts);
        int remainingUserAttempts = email != null ?
                Math.max(0, maxAttemptsPerUser - (int)userAttempts) : maxAttemptsPerUser;

        LocalDateTime ipBlockUntil = isIpBlocked(ipAddress) ?
                LocalDateTime.now().plusMinutes(blockDurationMinutes) : null;
        LocalDateTime userBlockUntil = isUserBlocked(email) ?
                LocalDateTime.now().plusMinutes(blockDurationMinutes) : null;

        return RateLimitInfo.builder()
                .ipAddress(ipAddress)
                .email(email)
                .ipAttempts((int)ipAttempts)
                .userAttempts((int)userAttempts)
                .remainingIpAttempts(remainingIpAttempts)
                .remainingUserAttempts(remainingUserAttempts)
                .windowMinutes(windowMinutes)
                .ipBlockedUntil(ipBlockUntil)
                .userBlockedUntil(userBlockUntil)
                .build();
    }

    @Override
    @Transactional
    public void clearFailedAttemptsForUser(String email) {
        if (email != null) {
            LocalDateTime cutoff = LocalDateTime.now().minusMinutes(windowMinutes);
            loginAttemptRepository.clearFailedAttemptsForUser(email, cutoff);
            log.debug("Cleared failed attempts for user: {}", email);
        }
    }

    @Override
    @Transactional
    public void clearFailedAttemptsForIp(String ipAddress) {
        LocalDateTime cutoff = LocalDateTime.now().minusMinutes(windowMinutes);
        loginAttemptRepository.clearFailedAttemptsForIp(ipAddress, cutoff);
        log.debug("Cleared failed attempts for IP: {}", ipAddress);
    }

    @Override
    @Transactional
    public void blockIpExplicitly(String ipAddress, int durationMinutes, String reason) {
        LoginAttempt blockRecord = LoginAttempt.builder()
                .ipAddress(ipAddress)
                .attemptType(AttemptType.LOGIN)
                .success(false)
                .blocked(true)
                .blockType(BlockType.IP_BLOCKED)
                .blockReason(reason)
                .blockedUntil(LocalDateTime.now().plusMinutes(durationMinutes))
                .attemptTime(LocalDateTime.now())
                .build();

        loginAttemptRepository.save(blockRecord);
        log.warn("IP {} explicitly blocked for {} minutes. Reason: {}", ipAddress, durationMinutes, reason);
    }

    @Override
    @Transactional
    public void blockUserExplicitly(String email, int durationMinutes, String reason) {
        User user = userRepository.findByEmail(email);
        if (user != null) {
            LoginAttempt blockRecord = LoginAttempt.builder()
                    .email(email)
                    .attemptType(AttemptType.LOGIN)
                    .success(false)
                    .blocked(true)
                    .blockType(BlockType.USER_BLOCKED)
                    .blockReason(reason)
                    .blockedUntil(LocalDateTime.now().plusMinutes(durationMinutes))
                    .attemptTime(LocalDateTime.now())
                    .build();

            loginAttemptRepository.save(blockRecord);
            log.warn("User {} explicitly blocked for {} minutes. Reason: {}", email, durationMinutes, reason);
        }
    }

    @Override
    @Transactional
    public void unblockIp(String ipAddress) {
        loginAttemptRepository.clearBlocksForIp(ipAddress);
        clearFailedAttemptsForIp(ipAddress);
        log.info("IP {} has been unblocked", ipAddress);
    }

    @Override
    @Transactional
    public void unblockUser(String email) {
        loginAttemptRepository.clearBlocksForUser(email);
        clearFailedAttemptsForUser(email);
        log.info("User {} has been unblocked", email);
    }

    private void checkAndBlockIfNecessary(String ipAddress, String email, AttemptType attemptType) {
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(windowMinutes);

        // Verificar intentos por IP
        long ipAttempts = loginAttemptRepository.countFailedAttemptsByIp(ipAddress, windowStart);
        if (ipAttempts >= maxAttemptsPerIp) {
            int blockDuration = calculateBlockDuration(ipAttempts, BlockType.IP_BLOCKED);
            blockIpExplicitly(ipAddress, blockDuration,
                    String.format("Automatic block after %d failed attempts", ipAttempts));
        }

        // Verificar intentos por usuario
        if (email != null) {
            long userAttempts = loginAttemptRepository.countFailedAttemptsByUser(email, windowStart);
            if (userAttempts >= maxAttemptsPerUser) {
                int blockDuration = calculateBlockDuration(userAttempts, BlockType.USER_BLOCKED);
                blockUserExplicitly(email, blockDuration,
                        String.format("Automatic block after %d failed attempts", userAttempts));
            }
        }
    }

    private int calculateBlockDuration(long attemptCount, BlockType blockType) {
        if (!progressiveBlock) {
            return blockDurationMinutes;
        }

        // Bloqueo progresivo: aumenta la duración según el número de intentos
        long excessAttempts = blockType == BlockType.IP_BLOCKED ?
                attemptCount - maxAttemptsPerIp : attemptCount - maxAttemptsPerUser;

        return (int) Math.min(blockDurationMinutes * (1 + excessAttempts / 5),
                blockDurationMinutes * 4); // Máximo 4 veces la duración base
    }

    @Override
    @Scheduled(cron = "0 0 2 * * ?") // Ejecutar diariamente a las 2:00 AM
    @Transactional
    public void cleanupOldAttempts() {
        log.info("Starting cleanup of old login attempts");

        try {
            LocalDateTime cutoff = LocalDateTime.now().minusDays(7); // Mantener 7 días de historia
            int deletedRecords = loginAttemptRepository.deleteOldAttempts(cutoff);
            log.info("Cleaned up {} old login attempt records", deletedRecords);

            // Limpiar bloqueos expirados
            int expiredBlocks = loginAttemptRepository.clearExpiredBlocks(LocalDateTime.now());
            log.info("Cleared {} expired blocks", expiredBlocks);

        } catch (Exception e) {
            log.error("Error during login attempts cleanup: {}", e.getMessage(), e);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public List<LoginAttempt> getRecentFailedAttempts(String ipAddress, String email, int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);

        if (email != null && ipAddress != null) {
            return loginAttemptRepository.findFailedAttemptsByUserAndIp(email, ipAddress, since);
        } else if (email != null) {
            return loginAttemptRepository.findFailedAttemptsByUser(email, since);
        } else if (ipAddress != null) {
            return loginAttemptRepository.findFailedAttemptsByIp(ipAddress, since);
        }

        return List.of();
    }
}
