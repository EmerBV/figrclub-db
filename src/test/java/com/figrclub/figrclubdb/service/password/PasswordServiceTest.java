package com.figrclub.figrclubdb.service.password;

import com.figrclub.figrclubdb.domain.model.PasswordResetToken;
import com.figrclub.figrclubdb.domain.model.Role;
import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.enums.UserType;
import com.figrclub.figrclubdb.exceptions.PasswordException;
import com.figrclub.figrclubdb.repository.PasswordResetTokenRepository;
import com.figrclub.figrclubdb.repository.UserRepository;
import com.figrclub.figrclubdb.request.PasswordChangeRequest;
import com.figrclub.figrclubdb.request.PasswordResetConfirmRequest;
import com.figrclub.figrclubdb.request.PasswordResetRequest;
import com.figrclub.figrclubdb.service.user.IUserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Test para PasswordService CORREGIDO para sistema de rol único inmutable
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PasswordServiceTest {

    @Mock
    private IUserService userService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordResetTokenRepository tokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private PasswordService passwordService;

    private User testUser;
    private Role userRole;

    @BeforeEach
    void setUp() {
        // Configurar propiedades del servicio
        ReflectionTestUtils.setField(passwordService, "tokenExpirationHours", 24);
        ReflectionTestUtils.setField(passwordService, "tokenLength", 32);

        // Crear rol de prueba
        userRole = new Role("ROLE_USER");
        userRole.setId(1L);

        // CORREGIDO: Crear usuario con rol único en lugar de Set<Role>
        testUser = new User();
        testUser.setId(1L);
        testUser.setFirstName("John");
        testUser.setLastName("Doe");
        testUser.setEmail("john.doe@example.com");
        testUser.setPassword("$2a$10$encodedCurrentPassword");
        testUser.setEnabled(true);
        testUser.setRole(userRole); // CORREGIDO: rol único
        testUser.setUserType(UserType.INDIVIDUAL);
        testUser.setSubscriptionType(SubscriptionType.FREE);
        testUser.setAccountNonExpired(true);
        testUser.setAccountNonLocked(true);
        testUser.setCredentialsNonExpired(true);
    }

    @Test
    void changePassword_Success() {
        // Arrange
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setCurrentPassword("currentPassword");
        request.setNewPassword("NewPassword123!");
        request.setConfirmPassword("NewPassword123!");

        when(userService.getAuthenticatedUser()).thenReturn(testUser);
        when(passwordEncoder.matches("currentPassword", testUser.getPassword())).thenReturn(true);
        when(passwordEncoder.matches("NewPassword123!", testUser.getPassword())).thenReturn(false);
        when(passwordEncoder.encode("NewPassword123!")).thenReturn("$2a$10$encodedNewPassword");
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // Act & Assert
        assertDoesNotThrow(() -> passwordService.changePassword(request));

        // Verify
        verify(userRepository).save(testUser);
        verify(passwordEncoder).encode("NewPassword123!");
    }

    @Test
    void changePassword_WrongCurrentPassword_ThrowsException() {
        // Arrange
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setCurrentPassword("wrongPassword");
        request.setNewPassword("NewPassword123!");
        request.setConfirmPassword("NewPassword123!");

        when(userService.getAuthenticatedUser()).thenReturn(testUser);
        when(passwordEncoder.matches("wrongPassword", testUser.getPassword())).thenReturn(false);

        // Act & Assert
        assertThrows(PasswordException.class, () -> passwordService.changePassword(request));

        // Verify
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void changePassword_SamePassword_ThrowsException() {
        // Arrange
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setCurrentPassword("currentPassword");
        request.setNewPassword("currentPassword");
        request.setConfirmPassword("currentPassword");

        when(userService.getAuthenticatedUser()).thenReturn(testUser);
        when(passwordEncoder.matches("currentPassword", testUser.getPassword())).thenReturn(true);

        // Act & Assert
        assertThrows(PasswordException.class, () -> passwordService.changePassword(request));

        // Verify
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void changePassword_PasswordMismatch_ThrowsException() {
        // Arrange
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setCurrentPassword("currentPassword");
        request.setNewPassword("NewPassword123!");
        request.setConfirmPassword("DifferentPassword123!");

        // Act & Assert
        assertThrows(PasswordException.class, () -> passwordService.changePassword(request));

        // Verify
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void requestPasswordReset_Success() {
        // Arrange
        PasswordResetRequest request = new PasswordResetRequest();
        request.setEmail("john.doe@example.com");

        when(userRepository.findByEmail("john.doe@example.com")).thenReturn(testUser);
        when(tokenRepository.countValidTokensByUser(eq(testUser), any(LocalDateTime.class))).thenReturn(0L);
        when(tokenRepository.save(any(PasswordResetToken.class))).thenAnswer(invocation -> {
            PasswordResetToken token = invocation.getArgument(0);
            token.setId(1L);
            return token;
        });

        // Act & Assert
        assertDoesNotThrow(() -> passwordService.requestPasswordReset(request));

        // Verify
        verify(tokenRepository).save(any(PasswordResetToken.class));
    }

    @Test
    void requestPasswordReset_UserNotFound_NoExceptionThrown() {
        // Arrange
        PasswordResetRequest request = new PasswordResetRequest();
        request.setEmail("nonexistent@example.com");

        when(userRepository.findByEmail("nonexistent@example.com")).thenReturn(null);

        // Act & Assert - CORREGIDO: No debería lanzar excepción por razones de seguridad
        assertDoesNotThrow(() -> passwordService.requestPasswordReset(request));

        // Verify - No debería guardar ningún token
        verify(tokenRepository, never()).save(any(PasswordResetToken.class));
    }

    @Test
    void requestPasswordReset_TooManyActiveTokens_ThrowsException() {
        // Arrange
        PasswordResetRequest request = new PasswordResetRequest();
        request.setEmail("john.doe@example.com");

        when(userRepository.findByEmail("john.doe@example.com")).thenReturn(testUser);
        when(tokenRepository.countValidTokensByUser(eq(testUser), any(LocalDateTime.class))).thenReturn(3L);

        // Act & Assert
        assertThrows(PasswordException.class, () -> passwordService.requestPasswordReset(request));

        // Verify
        verify(tokenRepository, never()).save(any(PasswordResetToken.class));
    }

    @Test
    void confirmPasswordReset_Success() {
        // Arrange
        PasswordResetConfirmRequest request = new PasswordResetConfirmRequest();
        request.setToken("validToken123");
        request.setNewPassword("NewPassword123!");
        request.setConfirmPassword("NewPassword123!");

        PasswordResetToken token = PasswordResetToken.builder()
                .id(1L)
                .token("validToken123")
                .user(testUser)
                .expiresAt(LocalDateTime.now().plusHours(1))
                .used(false)
                .build();

        when(tokenRepository.findByToken("validToken123")).thenReturn(Optional.of(token));
        when(passwordEncoder.encode("NewPassword123!")).thenReturn("$2a$10$encodedNewPassword");
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(tokenRepository.save(any(PasswordResetToken.class))).thenReturn(token);

        // Act & Assert
        assertDoesNotThrow(() -> passwordService.confirmPasswordReset(request));

        // Verify
        verify(userRepository).save(testUser);
        verify(tokenRepository).save(token);
        assertTrue(token.isUsed());
    }

    @Test
    void confirmPasswordReset_InvalidToken_ThrowsException() {
        // Arrange
        PasswordResetConfirmRequest request = new PasswordResetConfirmRequest();
        request.setToken("invalidToken");
        request.setNewPassword("NewPassword123!");
        request.setConfirmPassword("NewPassword123!");

        when(tokenRepository.findByToken("invalidToken")).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(PasswordException.class, () -> passwordService.confirmPasswordReset(request));

        // Verify
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void confirmPasswordReset_ExpiredToken_ThrowsException() {
        // Arrange
        PasswordResetConfirmRequest request = new PasswordResetConfirmRequest();
        request.setToken("expiredToken");
        request.setNewPassword("NewPassword123!");
        request.setConfirmPassword("NewPassword123!");

        PasswordResetToken expiredToken = PasswordResetToken.builder()
                .id(1L)
                .token("expiredToken")
                .user(testUser)
                .expiresAt(LocalDateTime.now().minusHours(1)) // Expirado
                .used(false)
                .build();

        when(tokenRepository.findByToken("expiredToken")).thenReturn(Optional.of(expiredToken));

        // Act & Assert
        assertThrows(PasswordException.class, () -> passwordService.confirmPasswordReset(request));

        // Verify
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void confirmPasswordReset_UsedToken_ThrowsException() {
        // Arrange
        PasswordResetConfirmRequest request = new PasswordResetConfirmRequest();
        request.setToken("usedToken");
        request.setNewPassword("NewPassword123!");
        request.setConfirmPassword("NewPassword123!");

        PasswordResetToken usedToken = PasswordResetToken.builder()
                .id(1L)
                .token("usedToken")
                .user(testUser)
                .expiresAt(LocalDateTime.now().plusHours(1))
                .used(true) // Ya usado
                .build();

        when(tokenRepository.findByToken("usedToken")).thenReturn(Optional.of(usedToken));

        // Act & Assert
        assertThrows(PasswordException.class, () -> passwordService.confirmPasswordReset(request));

        // Verify
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void confirmPasswordReset_PasswordMismatch_ThrowsException() {
        // Arrange
        PasswordResetConfirmRequest request = new PasswordResetConfirmRequest();
        request.setToken("validToken");
        request.setNewPassword("NewPassword123!");
        request.setConfirmPassword("DifferentPassword123!");

        PasswordResetToken token = PasswordResetToken.builder()
                .id(1L)
                .token("validToken")
                .user(testUser)
                .expiresAt(LocalDateTime.now().plusHours(1))
                .used(false)
                .build();

        when(tokenRepository.findByToken("validToken")).thenReturn(Optional.of(token));

        // Act & Assert
        assertThrows(PasswordException.class, () -> passwordService.confirmPasswordReset(request));

        // Verify
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void isValidResetToken_ValidToken_ReturnsTrue() {
        // Arrange
        when(tokenRepository.existsByTokenAndValidState(eq("validToken"), any(LocalDateTime.class))).thenReturn(true);

        // Act
        boolean result = passwordService.isValidResetToken("validToken");

        // Assert
        assertTrue(result);
    }

    @Test
    void isValidResetToken_InvalidToken_ReturnsFalse() {
        // Arrange
        when(tokenRepository.existsByTokenAndValidState(eq("invalidToken"), any(LocalDateTime.class))).thenReturn(false);

        // Act
        boolean result = passwordService.isValidResetToken("invalidToken");

        // Assert
        assertFalse(result);
    }

    @Test
    void isValidResetToken_ExpiredToken_ReturnsFalse() {
        // Arrange
        when(tokenRepository.existsByTokenAndValidState(eq("expiredToken"), any(LocalDateTime.class))).thenReturn(false);

        // Act
        boolean result = passwordService.isValidResetToken("expiredToken");

        // Assert
        assertFalse(result);
    }

    @Test
    void isValidResetToken_UsedToken_ReturnsFalse() {
        // Arrange
        when(tokenRepository.existsByTokenAndValidState(eq("usedToken"), any(LocalDateTime.class))).thenReturn(false);

        // Act
        boolean result = passwordService.isValidResetToken("usedToken");

        // Assert
        assertFalse(result);
    }

    @Test
    void validatePasswordsMatch_Success() {
        // Act & Assert
        assertDoesNotThrow(() -> passwordService.validatePasswordsMatch("password123", "password123"));
    }

    @Test
    void validatePasswordsMatch_Mismatch_ThrowsException() {
        // Act & Assert
        assertThrows(PasswordException.class,
                () -> passwordService.validatePasswordsMatch("password123", "differentPassword"));
    }

    @Test
    void generateResetToken_ReturnsNonNullToken() {
        // Act
        String token = passwordService.generateResetToken();

        // Assert
        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void generateResetToken_ReturnsDifferentTokensOnMultipleCalls() {
        // Act
        String token1 = passwordService.generateResetToken();
        String token2 = passwordService.generateResetToken();

        // Assert
        assertNotEquals(token1, token2);
    }
}
