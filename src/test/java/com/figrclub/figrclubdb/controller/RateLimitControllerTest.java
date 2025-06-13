package com.figrclub.figrclubdb.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.figrclub.figrclubdb.config.TestSecurityConfig;
import com.figrclub.figrclubdb.domain.model.LoginAttempt;
import com.figrclub.figrclubdb.dto.RateLimitInfo;
import com.figrclub.figrclubdb.request.BlockRequest;
import com.figrclub.figrclubdb.service.ratelimit.IRateLimitingService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean; // CORREGIDO: Nueva anotación
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(RateLimitController.class)
@Import(TestSecurityConfig.class)
class RateLimitControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean // CORREGIDO: Usar @MockitoBean en lugar de @MockBean
    private IRateLimitingService rateLimitingService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @WithMockUser
    void getRateLimitStatus_Success() throws Exception {
        // Arrange
        RateLimitInfo rateLimitInfo = RateLimitInfo.builder()
                .ipAddress("192.168.1.100")
                .remainingIpAttempts(5)
                .windowMinutes(15)
                .build();

        when(rateLimitingService.getRateLimitInfo(anyString(), any())).thenReturn(rateLimitInfo);
        when(rateLimitingService.isIpBlocked(anyString())).thenReturn(false);

        // Act & Assert
        mockMvc.perform(get("/figrclub/api/v1/rate-limit/status")) // CORREGIDO: Usar tu prefix correcto
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Rate limit status retrieved"))
                .andExpect(jsonPath("$.data.rateLimitInfo.remainingIpAttempts").value(5));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void getRecentAttempts_AsAdmin_Success() throws Exception {
        // Arrange
        List<LoginAttempt> attempts = List.of(new LoginAttempt(), new LoginAttempt());
        when(rateLimitingService.getRecentFailedAttempts(anyString(), anyString(), anyInt()))
                .thenReturn(attempts);

        // Act & Assert
        mockMvc.perform(get("/figrclub/api/v1/rate-limit/admin/attempts")
                        .param("ipAddress", "192.168.1.100")
                        .param("email", "test@example.com")
                        .param("hours", "24"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Recent attempts retrieved"))
                .andExpect(jsonPath("$.data.count").value(2)); // CORREGIDO: andExpect en lugar de andExpected
    }

    @Test
    @WithMockUser(roles = "USER")
    void getRecentAttempts_AsUser_Forbidden() throws Exception {
        // Act & Assert
        mockMvc.perform(get("/figrclub/api/v1/rate-limit/admin/attempts"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void blockIp_AsAdmin_Success() throws Exception {
        // Arrange
        BlockRequest request = new BlockRequest();
        request.setIdentifier("192.168.1.100");
        request.setDurationMinutes(60);
        request.setReason("Suspicious activity");

        doNothing().when(rateLimitingService).blockIpExplicitly(anyString(), anyInt(), anyString());

        // Act & Assert
        mockMvc.perform(post("/figrclub/api/v1/rate-limit/admin/block-ip")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("IP blocked successfully"));

        verify(rateLimitingService).blockIpExplicitly("192.168.1.100", 60, "Suspicious activity");
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void blockUser_AsAdmin_Success() throws Exception {
        // Arrange
        BlockRequest request = new BlockRequest();
        request.setIdentifier("user@example.com");
        request.setDurationMinutes(30);
        request.setReason("Multiple failed logins");

        doNothing().when(rateLimitingService).blockUserExplicitly(anyString(), anyInt(), anyString());

        // Act & Assert
        mockMvc.perform(post("/figrclub/api/v1/rate-limit/admin/block-user")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User blocked successfully"));

        verify(rateLimitingService).blockUserExplicitly("user@example.com", 30, "Multiple failed logins");
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void unblockIp_AsAdmin_Success() throws Exception {
        // Arrange
        doNothing().when(rateLimitingService).unblockIp(anyString());

        // Act & Assert
        mockMvc.perform(delete("/figrclub/api/v1/rate-limit/admin/unblock-ip/192.168.1.100")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("IP unblocked successfully"));

        verify(rateLimitingService).unblockIp("192.168.1.100");
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void unblockUser_AsAdmin_Success() throws Exception {
        // Arrange
        doNothing().when(rateLimitingService).unblockUser(anyString());

        // Act & Assert
        mockMvc.perform(delete("/figrclub/api/v1/rate-limit/admin/unblock-user/user@example.com")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User unblocked successfully"));

        verify(rateLimitingService).unblockUser("user@example.com");
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void blockIp_InvalidRequest_BadRequest() throws Exception {
        // Arrange
        BlockRequest request = new BlockRequest();
        // Dejar campos vacíos para provocar error de validación

        // Act & Assert
        mockMvc.perform(post("/figrclub/api/v1/rate-limit/admin/block-ip")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void cleanupOldAttempts_AsAdmin_Success() throws Exception {
        // Arrange
        doNothing().when(rateLimitingService).cleanupOldAttempts();

        // Act & Assert
        mockMvc.perform(post("/figrclub/api/v1/rate-limit/admin/cleanup")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Cleanup completed successfully"));

        verify(rateLimitingService).cleanupOldAttempts();
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void clearFailedAttempts_AsAdmin_Success() throws Exception {
        // Arrange
        doNothing().when(rateLimitingService).clearFailedAttemptsForUser(anyString());

        // Act & Assert
        mockMvc.perform(post("/figrclub/api/v1/rate-limit/admin/clear-failed/user@example.com")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Failed attempts cleared successfully"));

        verify(rateLimitingService).clearFailedAttemptsForUser("user@example.com");
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void clearFailedAttemptsForIp_AsAdmin_Success() throws Exception {
        // Arrange
        doNothing().when(rateLimitingService).clearFailedAttemptsForIp(anyString());

        // Act & Assert
        mockMvc.perform(post("/figrclub/api/v1/rate-limit/admin/clear-failed-ip/192.168.1.100")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Failed attempts cleared successfully"));

        verify(rateLimitingService).clearFailedAttemptsForIp("192.168.1.100");
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void checkDetailedStatus_AsAdmin_Success() throws Exception {
        // Arrange
        RateLimitInfo ipInfo = RateLimitInfo.builder()
                .ipAddress("192.168.1.100")
                .remainingIpAttempts(8)
                .build();

        RateLimitInfo userInfo = RateLimitInfo.builder()
                .email("test@example.com")
                .remainingUserAttempts(3)
                .build();

        when(rateLimitingService.isIpBlocked("192.168.1.100")).thenReturn(false);
        when(rateLimitingService.isUserBlocked("test@example.com")).thenReturn(false);
        when(rateLimitingService.getRateLimitInfo("192.168.1.100", null)).thenReturn(ipInfo);
        when(rateLimitingService.getRateLimitInfo(null, "test@example.com")).thenReturn(userInfo);

        // Act & Assert
        mockMvc.perform(get("/figrclub/api/v1/rate-limit/admin/check-status")
                        .param("ipAddress", "192.168.1.100")
                        .param("email", "test@example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Detailed status retrieved"))
                .andExpect(jsonPath("$.data.ipBlocked").value(false))
                .andExpect(jsonPath("$.data.userBlocked").value(false));
    }

    @Test
    @WithMockUser
    void getRateLimitStatus_WithEmail_Success() throws Exception {
        // Arrange
        RateLimitInfo rateLimitInfo = RateLimitInfo.builder()
                .ipAddress("192.168.1.100")
                .email("test@example.com")
                .remainingIpAttempts(5)
                .remainingUserAttempts(3)
                .windowMinutes(15)
                .build();

        when(rateLimitingService.getRateLimitInfo(anyString(), eq("test@example.com"))).thenReturn(rateLimitInfo);
        when(rateLimitingService.isIpBlocked(anyString())).thenReturn(false);
        when(rateLimitingService.isUserBlocked("test@example.com")).thenReturn(false);

        // Act & Assert
        mockMvc.perform(get("/figrclub/api/v1/rate-limit/status")
                        .param("email", "test@example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Rate limit status retrieved"))
                .andExpect(jsonPath("$.data.rateLimitInfo.email").value("test@example.com"))
                .andExpect(jsonPath("$.data.userBlocked").value(false));
    }

    @Test
    @WithMockUser
    void getRateLimitStatus_ErrorHandling_ReturnsInternalServerError() throws Exception {
        // Arrange
        when(rateLimitingService.getRateLimitInfo(anyString(), any()))
                .thenThrow(new RuntimeException("Database error"));

        // Act & Assert
        mockMvc.perform(get("/figrclub/api/v1/rate-limit/status"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.message").value("Error retrieving rate limit status"));
    }
}
