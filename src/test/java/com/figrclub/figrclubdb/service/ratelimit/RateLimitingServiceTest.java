package com.figrclub.figrclubdb.service.ratelimit;

import com.figrclub.figrclubdb.domain.model.LoginAttempt;
import com.figrclub.figrclubdb.domain.model.Role;
import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.RateLimitInfo;
import com.figrclub.figrclubdb.enums.AttemptType;
import com.figrclub.figrclubdb.enums.BlockType;
import com.figrclub.figrclubdb.exceptions.RateLimitExceededException;
import com.figrclub.figrclubdb.repository.LoginAttemptRepository;
import com.figrclub.figrclubdb.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RateLimitingServiceTest {

    @Mock
    private LoginAttemptRepository loginAttemptRepository;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private RateLimitingService rateLimitingService;

    private User testUser;
    private final String testIp = "192.168.1.100";
    private final String testEmail = "test@example.com";

    @BeforeEach
    void setUp() {
        // Configurar propiedades del servicio
        ReflectionTestUtils.setField(rateLimitingService, "maxAttemptsPerIp", 5);
        ReflectionTestUtils.setField(rateLimitingService, "maxAttemptsPerUser", 3);
        ReflectionTestUtils.setField(rateLimitingService, "windowMinutes", 15);
        ReflectionTestUtils.setField(rateLimitingService, "blockDurationMinutes", 30);
        ReflectionTestUtils.setField(rateLimitingService, "progressiveBlock", true);

        // Crear usuario de prueba
        Role userRole = new Role("ROLE_USER");
        testUser = User.builder()
                .id(1L)
                .firstName("Test")
                .lastName("User")
                .email(testEmail)
                .password("encodedPassword")
                .roles(Set.of(userRole))
                .build();
    }

    @Test
    void recordFailedAttempt_Success() {
        // Arrange
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenReturn(new LoginAttempt());
        when(loginAttemptRepository.countFailedAttemptsByIp(eq(testIp), any(LocalDateTime.class))).thenReturn(1L);
        when(loginAttemptRepository.countFailedAttemptsByUser(eq(testEmail), any(LocalDateTime.class))).thenReturn(1L);

        // Act
        assertDoesNotThrow(() -> rateLimitingService.recordFailedAttempt(testIp, testEmail, AttemptType.LOGIN));

        // Assert
        verify(loginAttemptRepository).save(any(LoginAttempt.class));
        verify(loginAttemptRepository).countFailedAttemptsByIp(eq(testIp), any(LocalDateTime.class));
        verify(loginAttemptRepository).countFailedAttemptsByUser(eq(testEmail), any(LocalDateTime.class));
    }

    @Test
    void recordSuccessfulAttempt_ClearsFailedAttempts() {
        // Arrange
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenReturn(new LoginAttempt());
        doNothing().when(loginAttemptRepository).clearFailedAttemptsForUser(eq(testEmail), any(LocalDateTime.class));

        // Act
        rateLimitingService.recordSuccessfulAttempt(testIp, testEmail, AttemptType.LOGIN);

        // Assert
        verify(loginAttemptRepository).save(any(LoginAttempt.class));
        verify(loginAttemptRepository).clearFailedAttemptsForUser(eq(testEmail), any(LocalDateTime.class));
    }

    @Test
    void isIpBlocked_ExplicitlyBlocked_ReturnsTrue() {
        // Arrange
        when(loginAttemptRepository.isIpExplicitlyBlocked(eq(testIp), any(LocalDateTime.class))).thenReturn(true);

        // Act
        boolean result = rateLimitingService.isIpBlocked(testIp);

        // Assert
        assertTrue(result);
        verify(loginAttemptRepository).isIpExplicitlyBlocked(eq(testIp), any(LocalDateTime.class));
    }

    @Test
    void isIpBlocked_RateLimitExceeded_ReturnsTrue() {
        // Arrange
        when(loginAttemptRepository.isIpExplicitlyBlocked(eq(testIp), any(LocalDateTime.class))).thenReturn(false);
        when(loginAttemptRepository.countFailedAttemptsByIp(eq(testIp), any(LocalDateTime.class))).thenReturn(6L); // Excede el límite de 5

        // Act
        boolean result = rateLimitingService.isIpBlocked(testIp);

        // Assert
        assertTrue(result);
    }

    @Test
    void isIpBlocked_WithinLimits_ReturnsFalse() {
        // Arrange
        when(loginAttemptRepository.isIpExplicitlyBlocked(eq(testIp), any(LocalDateTime.class))).thenReturn(false);
        when(loginAttemptRepository.countFailedAttemptsByIp(eq(testIp), any(LocalDateTime.class))).thenReturn(2L);

        // Act
        boolean result = rateLimitingService.isIpBlocked(testIp);

        // Assert
        assertFalse(result);
    }

    @Test
    void isUserBlocked_ExplicitlyBlocked_ReturnsTrue() {
        // Arrange
        when(loginAttemptRepository.isUserExplicitlyBlocked(eq(testEmail), any(LocalDateTime.class))).thenReturn(true);

        // Act
        boolean result = rateLimitingService.isUserBlocked(testEmail);

        // Assert
        assertTrue(result);
    }

    @Test
    void isUserBlocked_RateLimitExceeded_ReturnsTrue() {
        // Arrange
        when(loginAttemptRepository.isUserExplicitlyBlocked(eq(testEmail), any(LocalDateTime.class))).thenReturn(false);
        when(loginAttemptRepository.countFailedAttemptsByUser(eq(testEmail), any(LocalDateTime.class))).thenReturn(4L); // Excede el límite de 3

        // Act
        boolean result = rateLimitingService.isUserBlocked(testEmail);

        // Assert
        assertTrue(result);
    }

    @Test
    void isUserBlocked_NullEmail_ReturnsFalse() {
        // Act
        boolean result = rateLimitingService.isUserBlocked(null);

        // Assert
        assertFalse(result);
        verifyNoInteractions(loginAttemptRepository);
    }

    @Test
    void validateRateLimit_IpBlocked_ThrowsException() {
        // Arrange
        when(loginAttemptRepository.isIpExplicitlyBlocked(eq(testIp), any(LocalDateTime.class))).thenReturn(true);

        // Act & Assert
        RateLimitExceededException exception = assertThrows(RateLimitExceededException.class,
                () -> rateLimitingService.validateRateLimit(testIp, testEmail, AttemptType.LOGIN));

        assertEquals(BlockType.IP_BLOCKED, exception.getBlockType());
        assertTrue(exception.getMessage().contains("Too many attempts from this IP address"));
    }

    @Test
    void validateRateLimit_UserBlocked_ThrowsException() {
        // Arrange
        when(loginAttemptRepository.isIpExplicitlyBlocked(eq(testIp), any(LocalDateTime.class))).thenReturn(false);
        when(loginAttemptRepository.countFailedAttemptsByIp(eq(testIp), any(LocalDateTime.class))).thenReturn(1L);
        when(loginAttemptRepository.isUserExplicitlyBlocked(eq(testEmail), any(LocalDateTime.class))).thenReturn(true);

        // Act & Assert
        RateLimitExceededException exception = assertThrows(RateLimitExceededException.class,
                () -> rateLimitingService.validateRateLimit(testIp, testEmail, AttemptType.LOGIN));

        assertEquals(BlockType.USER_BLOCKED, exception.getBlockType());
        assertTrue(exception.getMessage().contains("Too many failed attempts for this account"));
    }

    @Test
    void validateRateLimit_WithinLimits_NoException() {
        // Arrange
        when(loginAttemptRepository.isIpExplicitlyBlocked(eq(testIp), any(LocalDateTime.class))).thenReturn(false);
        when(loginAttemptRepository.countFailedAttemptsByIp(eq(testIp), any(LocalDateTime.class))).thenReturn(2L);
        when(loginAttemptRepository.isUserExplicitlyBlocked(eq(testEmail), any(LocalDateTime.class))).thenReturn(false);
        when(loginAttemptRepository.countFailedAttemptsByUser(eq(testEmail), any(LocalDateTime.class))).thenReturn(1L);

        // Act & Assert
        assertDoesNotThrow(() -> rateLimitingService.validateRateLimit(testIp, testEmail, AttemptType.LOGIN));
    }

    @Test
    void getRateLimitInfo_ReturnsCorrectInfo() {
        // Arrange
        when(loginAttemptRepository.countFailedAttemptsByIp(eq(testIp), any(LocalDateTime.class))).thenReturn(2L);
        when(loginAttemptRepository.countFailedAttemptsByUser(eq(testEmail), any(LocalDateTime.class))).thenReturn(1L);
        when(loginAttemptRepository.isIpExplicitlyBlocked(eq(testIp), any(LocalDateTime.class))).thenReturn(false);
        when(loginAttemptRepository.isUserExplicitlyBlocked(eq(testEmail), any(LocalDateTime.class))).thenReturn(false);

        // Act
        RateLimitInfo info = rateLimitingService.getRateLimitInfo(testIp, testEmail);

        // Assert
        assertNotNull(info);
        assertEquals(testIp, info.getIpAddress());
        assertEquals(testEmail, info.getEmail());
        assertEquals(2, info.getIpAttempts());
        assertEquals(1, info.getUserAttempts());
        assertEquals(3, info.getRemainingIpAttempts()); // 5 - 2
        assertEquals(2, info.getRemainingUserAttempts()); // 3 - 1
        assertEquals(15, info.getWindowMinutes());
    }

    @Test
    void blockIpExplicitly_CreatesBlockRecord() {
        // Arrange
        String reason = "Suspicious activity";
        int duration = 60;
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenReturn(new LoginAttempt());

        // Act
        rateLimitingService.blockIpExplicitly(testIp, duration, reason);

        // Assert
        verify(loginAttemptRepository).save(argThat(attempt ->
                attempt.getIpAddress().equals(testIp) &&
                        attempt.isBlocked() &&
                        attempt.getBlockType() == BlockType.IP_BLOCKED &&
                        attempt.getBlockReason().equals(reason)
        ));
    }

    @Test
    void blockUserExplicitly_UserExists_CreatesBlockRecord() {
        // Arrange
        String reason = "Multiple failed logins";
        int duration = 60;
        when(userRepository.findByEmail(testEmail)).thenReturn(testUser);
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenReturn(new LoginAttempt());

        // Act
        rateLimitingService.blockUserExplicitly(testEmail, duration, reason);

        // Assert
        verify(userRepository).findByEmail(testEmail);
        verify(loginAttemptRepository).save(argThat(attempt ->
                attempt.getEmail().equals(testEmail) &&
                        attempt.isBlocked() &&
                        attempt.getBlockType() == BlockType.USER_BLOCKED &&
                        attempt.getBlockReason().equals(reason)
        ));
    }

    @Test
    void blockUserExplicitly_UserNotExists_NoBlockRecord() {
        // Arrange
        String reason = "Multiple failed logins";
        int duration = 60;
        when(userRepository.findByEmail(testEmail)).thenReturn(null);

        // Act
        rateLimitingService.blockUserExplicitly(testEmail, duration, reason);

        // Assert
        verify(userRepository).findByEmail(testEmail);
        verify(loginAttemptRepository, never()).save(any(LoginAttempt.class));
    }

    @Test
    void unblockIp_ClearsBlocksAndAttempts() {
        // Arrange
        doNothing().when(loginAttemptRepository).clearBlocksForIp(testIp);
        doNothing().when(loginAttemptRepository).clearFailedAttemptsForIp(eq(testIp), any(LocalDateTime.class));

        // Act
        rateLimitingService.unblockIp(testIp);

        // Assert
        verify(loginAttemptRepository).clearBlocksForIp(testIp);
        verify(loginAttemptRepository).clearFailedAttemptsForIp(eq(testIp), any(LocalDateTime.class));
    }

    @Test
    void unblockUser_ClearsBlocksAndAttempts() {
        // Arrange
        doNothing().when(loginAttemptRepository).clearBlocksForUser(testEmail);
        doNothing().when(loginAttemptRepository).clearFailedAttemptsForUser(eq(testEmail), any(LocalDateTime.class));

        // Act
        rateLimitingService.unblockUser(testEmail);

        // Assert
        verify(loginAttemptRepository).clearBlocksForUser(testEmail);
        verify(loginAttemptRepository).clearFailedAttemptsForUser(eq(testEmail), any(LocalDateTime.class));
    }

    @Test
    void cleanupOldAttempts_DeletesOldRecords() {
        // Arrange
        when(loginAttemptRepository.deleteOldAttempts(any(LocalDateTime.class))).thenReturn(10);
        when(loginAttemptRepository.clearExpiredBlocks(any(LocalDateTime.class))).thenReturn(2);

        // Act
        rateLimitingService.cleanupOldAttempts();

        // Assert
        verify(loginAttemptRepository).deleteOldAttempts(any(LocalDateTime.class));
        verify(loginAttemptRepository).clearExpiredBlocks(any(LocalDateTime.class));
    }

    @Test
    void getRecentFailedAttempts_WithBothParams_ReturnsAttempts() {
        // Arrange
        List<LoginAttempt> expectedAttempts = List.of(new LoginAttempt(), new LoginAttempt());
        when(loginAttemptRepository.findFailedAttemptsByUserAndIp(eq(testEmail), eq(testIp), any(LocalDateTime.class)))
                .thenReturn(expectedAttempts);

        // Act
        List<LoginAttempt> result = rateLimitingService.getRecentFailedAttempts(testIp, testEmail, 24);

        // Assert
        assertEquals(expectedAttempts, result);
        verify(loginAttemptRepository).findFailedAttemptsByUserAndIp(eq(testEmail), eq(testIp), any(LocalDateTime.class));
    }

    @Test
    void getRecentFailedAttempts_WithEmailOnly_ReturnsAttempts() {
        // Arrange
        List<LoginAttempt> expectedAttempts = List.of(new LoginAttempt());
        when(loginAttemptRepository.findFailedAttemptsByUser(eq(testEmail), any(LocalDateTime.class)))
                .thenReturn(expectedAttempts);

        // Act
        List<LoginAttempt> result = rateLimitingService.getRecentFailedAttempts(null, testEmail, 24);

        // Assert
        assertEquals(expectedAttempts, result);
        verify(loginAttemptRepository).findFailedAttemptsByUser(eq(testEmail), any(LocalDateTime.class));
    }

    @Test
    void getRecentFailedAttempts_WithIpOnly_ReturnsAttempts() {
        // Arrange
        List<LoginAttempt> expectedAttempts = List.of(new LoginAttempt());
        when(loginAttemptRepository.findFailedAttemptsByIp(eq(testIp), any(LocalDateTime.class)))
                .thenReturn(expectedAttempts);

        // Act
        List<LoginAttempt> result = rateLimitingService.getRecentFailedAttempts(testIp, null, 24);

        // Assert
        assertEquals(expectedAttempts, result);
        verify(loginAttemptRepository).findFailedAttemptsByIp(eq(testIp), any(LocalDateTime.class));
    }

    @Test
    void getRecentFailedAttempts_WithoutParams_ReturnsEmptyList() {
        // Act
        List<LoginAttempt> result = rateLimitingService.getRecentFailedAttempts(null, null, 24);

        // Assert
        assertTrue(result.isEmpty());
        verifyNoInteractions(loginAttemptRepository);
    }
}
