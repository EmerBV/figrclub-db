package com.figrclub.figrclubdb.service.password;

import com.figrclub.figrclubdb.domain.model.PasswordResetToken;
import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.exceptions.PasswordException;
import com.figrclub.figrclubdb.exceptions.ResourceNotFoundException;
import com.figrclub.figrclubdb.repository.PasswordResetTokenRepository;
import com.figrclub.figrclubdb.repository.UserRepository;
import com.figrclub.figrclubdb.request.PasswordChangeRequest;
import com.figrclub.figrclubdb.request.PasswordResetConfirmRequest;
import com.figrclub.figrclubdb.request.PasswordResetRequest;
import com.figrclub.figrclubdb.service.user.IUserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordService implements IPasswordService {

    private final IUserService userService;
    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;

    // TODO: Implementar servicio de email cuando esté disponible
    // private final EmailService emailService;

    @Value("${app.password.reset.token.expiration:24}")
    private int tokenExpirationHours;

    @Value("${app.password.reset.token.length:32}")
    private int tokenLength;

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    @Transactional
    public void changePassword(PasswordChangeRequest request) {
        log.info("Processing password change request");

        // Validar que las contraseñas coincidan
        validatePasswordsMatch(request.getNewPassword(), request.getConfirmPassword());

        // Obtener usuario autenticado
        User user = userService.getAuthenticatedUser();

        // Verificar contraseña actual
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            log.warn("Invalid current password for user: {}", user.getEmail());
            throw new PasswordException("Current password is incorrect");
        }

        // Verificar que la nueva contraseña sea diferente a la actual
        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new PasswordException("New password must be different from current password");
        }

        // Actualizar contraseña
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // Invalidar todos los tokens de reset existentes
        tokenRepository.invalidateAllUserTokens(user);

        log.info("Password changed successfully for user: {}", user.getEmail());
    }

    @Override
    @Transactional
    public void requestPasswordReset(PasswordResetRequest request) {
        log.info("Processing password reset request for email: {}", request.getEmail());

        // Buscar usuario por email
        User user = userRepository.findByEmail(request.getEmail());
        if (user == null) {
            // Por seguridad, no revelamos si el email existe o no
            log.warn("Password reset requested for non-existent email: {}", request.getEmail());
            return; // Silenciosamente no hacer nada
        }

        // Verificar límite de tokens válidos por usuario (máximo 3)
        long validTokens = tokenRepository.countValidTokensByUser(user, LocalDateTime.now());
        if (validTokens >= 3) {
            log.warn("Too many active reset tokens for user: {}", user.getEmail());
            throw new PasswordException("Too many password reset requests. Please try again later.");
        }

        // Generar nuevo token
        String token = generateResetToken();
        LocalDateTime expiresAt = LocalDateTime.now().plusHours(tokenExpirationHours);

        PasswordResetToken resetToken = PasswordResetToken.builder()
                .token(token)
                .user(user)
                .expiresAt(expiresAt)
                .build();

        tokenRepository.save(resetToken);

        // TODO: Enviar email con el token
        // emailService.sendPasswordResetEmail(user.getEmail(), token);

        log.info("Password reset token generated for user: {}", user.getEmail());
        log.debug("Reset token will expire at: {}", expiresAt); // Solo para desarrollo
    }

    @Override
    @Transactional
    public void confirmPasswordReset(PasswordResetConfirmRequest request) {
        log.info("Processing password reset confirmation with token");

        // Validar que las contraseñas coincidan
        validatePasswordsMatch(request.getNewPassword(), request.getConfirmPassword());

        // Buscar y validar token
        PasswordResetToken resetToken = tokenRepository.findByToken(request.getToken())
                .orElseThrow(() -> new PasswordException("Invalid or expired reset token"));

        if (!resetToken.isValid()) {
            log.warn("Attempt to use invalid/expired token: {}", request.getToken());
            throw new PasswordException("Invalid or expired reset token");
        }

        User user = resetToken.getUser();

        // Verificar que la nueva contraseña sea diferente a la actual
        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new PasswordException("New password must be different from current password");
        }

        // Actualizar contraseña
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // Marcar token como usado
        resetToken.markAsUsed();
        tokenRepository.save(resetToken);

        // Invalidar todos los demás tokens del usuario
        tokenRepository.invalidateAllUserTokens(user);

        log.info("Password reset completed successfully for user: {}", user.getEmail());
    }

    @Override
    public void validatePasswordsMatch(String password, String confirmPassword) {
        if (!password.equals(confirmPassword)) {
            throw new PasswordException("Passwords do not match");
        }
    }

    @Override
    public String generateResetToken() {
        byte[] tokenBytes = new byte[tokenLength];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(tokenBytes);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isValidResetToken(String token) {
        return tokenRepository.existsByTokenAndValidState(token, LocalDateTime.now());
    }

    @Override
    @Transactional
    @Scheduled(cron = "0 0 2 * * ?") // Ejecutar diariamente a las 2:00 AM
    public void cleanupExpiredTokens() {
        log.info("Starting cleanup of expired password reset tokens");

        try {
            tokenRepository.deleteExpiredTokens(LocalDateTime.now());
            log.info("Expired password reset tokens cleaned up successfully");
        } catch (Exception e) {
            log.error("Error during token cleanup: {}", e.getMessage(), e);
        }
    }
}
