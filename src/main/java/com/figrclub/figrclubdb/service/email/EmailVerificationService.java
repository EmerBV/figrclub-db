package com.figrclub.figrclubdb.service.email;

import com.figrclub.figrclubdb.domain.model.EmailVerificationToken;
import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.exceptions.ResourceNotFoundException;
import com.figrclub.figrclubdb.exceptions.TokenExpiredException;
import com.figrclub.figrclubdb.exceptions.TokenAlreadyUsedException;
import com.figrclub.figrclubdb.repository.EmailVerificationTokenRepository;
import com.figrclub.figrclubdb.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * Servicio para manejo de verificación de email
 * Gestiona tokens de verificación y proceso de verificación
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailVerificationService {

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${app.email.verification.token.expiry-hours:24}")
    private int tokenExpiryHours;

    @Value("${app.email.verification.max-attempts:3}")
    private int maxVerificationAttempts;

    @Value("${app.email.verification.resend-cooldown-minutes:5}")
    private int resendCooldownMinutes;

    /**
     * Genera y envía token de verificación para un usuario
     */
    @Transactional
    public CompletableFuture<Boolean> generateAndSendVerificationToken(User user) {
        try {
            log.info("Generating verification token for user: {}", user.getEmail());

            // Verificar si ya existe un token válido
            Optional<EmailVerificationToken> existingToken = tokenRepository
                    .findValidTokenByUser(user, LocalDateTime.now());

            if (existingToken.isPresent()) {
                // Si existe un token válido reciente, verificar cooldown
                EmailVerificationToken token = existingToken.get();
                if (token.getCreatedAt().plusMinutes(resendCooldownMinutes).isAfter(LocalDateTime.now())) {
                    log.warn("Token generation attempted too soon for user: {}. Cooldown active.", user.getEmail());
                    return CompletableFuture.completedFuture(false);
                }
            }

            // Verificar límite de intentos
            long activeTokens = tokenRepository.countActiveTokensByUser(user, LocalDateTime.now());
            if (activeTokens >= maxVerificationAttempts) {
                log.warn("Maximum verification attempts reached for user: {}", user.getEmail());
                return CompletableFuture.completedFuture(false);
            }

            // Generar nuevo token
            String tokenValue = generateSecureToken();
            LocalDateTime expiryDate = LocalDateTime.now().plusHours(tokenExpiryHours);

            EmailVerificationToken verificationToken = EmailVerificationToken.builder()
                    .user(user)
                    .token(tokenValue)
                    .expiryDate(expiryDate)
                    .used(false)
                    .build();

            tokenRepository.save(verificationToken);

            // Enviar email de verificación
            return emailService.sendVerificationEmail(
                    user.getEmail(),
                    user.getFirstName(),
                    tokenValue
            );

        } catch (Exception e) {
            log.error("Error generating verification token for user {}: {}", user.getEmail(), e.getMessage(), e);
            return CompletableFuture.completedFuture(false);
        }
    }

    /**
     * Reenvía token de verificación
     */
    @Transactional
    public CompletableFuture<Boolean> resendVerificationToken(String email) {
        try {
            User user = userRepository.findByEmail(email);
            if (user == null) {
                throw new ResourceNotFoundException("Usuario no encontrado: " + email);
            }

            // Si el usuario ya está verificado, no enviamos token
            if (user.isEnabled()) {
                log.info("User {} is already verified", email);
                return CompletableFuture.completedFuture(false);
            }

            return generateAndSendVerificationToken(user);

        } catch (Exception e) {
            log.error("Error resending verification token for {}: {}", email, e.getMessage(), e);
            return CompletableFuture.completedFuture(false);
        }
    }

    /**
     * Verifica un token de verificación
     */
    @Transactional
    public boolean verifyEmail(String tokenValue, String ipAddress, String userAgent) {
        try {
            log.info("Verifying email token: {}", tokenValue);

            Optional<EmailVerificationToken> tokenOpt = tokenRepository.findByToken(tokenValue);
            if (tokenOpt.isEmpty()) {
                log.warn("Token not found: {}", tokenValue);
                return false;
            }

            EmailVerificationToken token = tokenOpt.get();
            User user = token.getUser();

            // Verificar si el token ya fue usado
            if (token.isUsed()) {
                log.warn("Token already used for user: {}", user.getEmail());
                throw new TokenAlreadyUsedException("El token de verificación ya fue utilizado");
            }

            // Verificar si el token ha expirado
            if (token.isExpired()) {
                log.warn("Expired token for user: {}", user.getEmail());
                throw new TokenExpiredException("El token de verificación ha expirado");
            }

            // Marcar token como usado
            token.markAsUsed(ipAddress, userAgent);
            tokenRepository.save(token);

            // Activar usuario si no estaba activo
            if (!user.isEnabled()) {
                user.setEnabled(true);
                userRepository.save(user);
                log.info("User {} verified and enabled", user.getEmail());

                // Enviar email de bienvenida
                emailService.sendWelcomeEmail(user.getEmail(), user.getFirstName());
            }

            // Invalidar otros tokens del usuario
            tokenRepository.invalidateUserTokens(user, LocalDateTime.now());

            log.info("Email verification successful for user: {}", user.getEmail());
            return true;

        } catch (TokenExpiredException | TokenAlreadyUsedException e) {
            log.warn("Token verification failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Error verifying email token {}: {}", tokenValue, e.getMessage(), e);
            return false;
        }
    }

    /**
     * Verifica el estado de verificación de un usuario
     */
    @Transactional(readOnly = true)
    public boolean isEmailVerified(String email) {
        User user = userRepository.findByEmail(email);
        return user != null && user.isEnabled();
    }

    /**
     * Obtiene información del token
     */
    @Transactional(readOnly = true)
    public Optional<EmailVerificationToken> getTokenInfo(String tokenValue) {
        return tokenRepository.findByToken(tokenValue);
    }

    /**
     * Limpia tokens expirados automáticamente
     */
    @Scheduled(fixedRate = 3600000) // Cada hora
    @Transactional
    public void cleanupExpiredTokens() {
        try {
            List<EmailVerificationToken> expiredTokens = tokenRepository.findExpiredTokens(LocalDateTime.now());
            if (!expiredTokens.isEmpty()) {
                tokenRepository.deleteExpiredTokens(LocalDateTime.now());
                log.info("Cleaned up {} expired verification tokens", expiredTokens.size());
            }
        } catch (Exception e) {
            log.error("Error during expired tokens cleanup: {}", e.getMessage(), e);
        }
    }

    /**
     * Genera un token seguro
     */
    private String generateSecureToken() {
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    /**
     * Obtiene estadísticas de verificación para un usuario
     */
    @Transactional(readOnly = true)
    public VerificationStats getVerificationStats(String email) {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            return VerificationStats.builder()
                    .userExists(false)
                    .isVerified(false)
                    .activeTokens(0)
                    .totalTokens(0)
                    .build();
        }

        long activeTokens = tokenRepository.countActiveTokensByUser(user, LocalDateTime.now());
        List<EmailVerificationToken> allTokens = tokenRepository.findByUserOrderByCreatedAtDesc(user);

        return VerificationStats.builder()
                .userExists(true)
                .isVerified(user.isEnabled())
                .activeTokens(activeTokens)
                .totalTokens(allTokens.size())
                .lastTokenCreated(allTokens.isEmpty() ? null : allTokens.get(0).getCreatedAt())
                .canResend(activeTokens < maxVerificationAttempts)
                .build();
    }

    /**
     * Record para estadísticas de verificación
     */
    public record VerificationStats(
            boolean userExists,
            boolean isVerified,
            long activeTokens,
            long totalTokens,
            LocalDateTime lastTokenCreated,
            boolean canResend
    ) {
        public static VerificationStatsBuilder builder() {
            return new VerificationStatsBuilder();
        }

        public static class VerificationStatsBuilder {
            private boolean userExists;
            private boolean isVerified;
            private long activeTokens;
            private long totalTokens;
            private LocalDateTime lastTokenCreated;
            private boolean canResend;

            public VerificationStatsBuilder userExists(boolean userExists) {
                this.userExists = userExists;
                return this;
            }

            public VerificationStatsBuilder isVerified(boolean isVerified) {
                this.isVerified = isVerified;
                return this;
            }

            public VerificationStatsBuilder activeTokens(long activeTokens) {
                this.activeTokens = activeTokens;
                return this;
            }

            public VerificationStatsBuilder totalTokens(long totalTokens) {
                this.totalTokens = totalTokens;
                return this;
            }

            public VerificationStatsBuilder lastTokenCreated(LocalDateTime lastTokenCreated) {
                this.lastTokenCreated = lastTokenCreated;
                return this;
            }

            public VerificationStatsBuilder canResend(boolean canResend) {
                this.canResend = canResend;
                return this;
            }

            public VerificationStats build() {
                return new VerificationStats(userExists, isVerified, activeTokens, totalTokens, lastTokenCreated, canResend);
            }
        }
    }
}
