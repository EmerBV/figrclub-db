package com.figrclub.figrclubdb.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.figrclub.figrclubdb.dto.RateLimitInfo;
import com.figrclub.figrclubdb.enums.AttemptType;
import com.figrclub.figrclubdb.enums.BlockType;
import com.figrclub.figrclubdb.exceptions.RateLimitExceededException;
import com.figrclub.figrclubdb.service.ratelimit.IRateLimitingService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Set;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RateLimitingFilterTest {

    @Mock
    private IRateLimitingService rateLimitingService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private RateLimitingFilter rateLimitingFilter;

    @BeforeEach
    void setUp() {
        // Configurar propiedades del filtro
        ReflectionTestUtils.setField(rateLimitingFilter, "rateLimitingEnabled", true);

        // Usar HashSet en lugar de Set.of para evitar problemas con nulos
        Set<String> whitelistIps = new HashSet<>();
        whitelistIps.add("127.0.0.1");
        whitelistIps.add("::1");
        ReflectionTestUtils.setField(rateLimitingFilter, "whitelistIps", whitelistIps);
    }

    @Test
    void doFilterInternal_RateLimitingDisabled_ContinuesChain() throws Exception {
        // Arrange
        ReflectionTestUtils.setField(rateLimitingFilter, "rateLimitingEnabled", false);
        // No necesitamos mockear request.getRequestURI() porque cuando está disabled no se usa

        // Act
        rateLimitingFilter.doFilterInternal(request, response, filterChain);

        // Assert
        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(rateLimitingService);
    }

    @Test
    void doFilterInternal_WhitelistedIP_ContinuesChain() throws Exception {
        // Arrange
        when(request.getRequestURI()).thenReturn("/api/v1/auth/login");
        when(request.getMethod()).thenReturn("POST");

        // Mockear correctamente la obtención de IP
        try (MockedStatic<com.figrclub.figrclubdb.util.IpUtils> ipUtilsMock =
                     mockStatic(com.figrclub.figrclubdb.util.IpUtils.class)) {

            ipUtilsMock.when(() -> com.figrclub.figrclubdb.util.IpUtils.getClientIpAddress(request))
                    .thenReturn("127.0.0.1");

            // Act
            rateLimitingFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain).doFilter(request, response);
            verifyNoInteractions(rateLimitingService);
        }
    }

    @Test
    void doFilterInternal_NonProtectedPath_ContinuesChain() throws Exception {
        // Arrange
        when(request.getRequestURI()).thenReturn("/api/v1/health");
        when(request.getMethod()).thenReturn("GET");

        try (MockedStatic<com.figrclub.figrclubdb.util.IpUtils> ipUtilsMock =
                     mockStatic(com.figrclub.figrclubdb.util.IpUtils.class)) {

            ipUtilsMock.when(() -> com.figrclub.figrclubdb.util.IpUtils.getClientIpAddress(request))
                    .thenReturn("192.168.1.100");

            // Act
            rateLimitingFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain).doFilter(request, response);
            verifyNoInteractions(rateLimitingService);
        }
    }

    @Test
    void doFilterInternal_ProtectedPath_ValidatesRateLimit() throws Exception {
        // Arrange
        when(request.getRequestURI()).thenReturn("/api/v1/auth/login");
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("email")).thenReturn("test@example.com");

        RateLimitInfo rateLimitInfo = RateLimitInfo.builder()
                .ipAddress("192.168.1.100")
                .email("test@example.com")
                .remainingIpAttempts(5)
                .remainingUserAttempts(3)
                .windowMinutes(15)
                .build();

        when(rateLimitingService.getRateLimitInfo(anyString(), anyString())).thenReturn(rateLimitInfo);
        doNothing().when(rateLimitingService).validateRateLimit(anyString(), anyString(), any(AttemptType.class));

        try (MockedStatic<com.figrclub.figrclubdb.util.IpUtils> ipUtilsMock =
                     mockStatic(com.figrclub.figrclubdb.util.IpUtils.class)) {

            ipUtilsMock.when(() -> com.figrclub.figrclubdb.util.IpUtils.getClientIpAddress(request))
                    .thenReturn("192.168.1.100");

            // Act
            rateLimitingFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(rateLimitingService).validateRateLimit("192.168.1.100", "test@example.com", AttemptType.LOGIN);
            verify(rateLimitingService).getRateLimitInfo("192.168.1.100", "test@example.com");
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void doFilterInternal_RateLimitExceeded_HandlesException() throws Exception {
        // Arrange
        when(request.getRequestURI()).thenReturn("/api/v1/auth/login");
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("email")).thenReturn("test@example.com");

        RateLimitExceededException exception = new RateLimitExceededException(
                "Too many attempts", BlockType.IP_BLOCKED, 30);

        doThrow(exception).when(rateLimitingService).validateRateLimit(anyString(), anyString(), any(AttemptType.class));

        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(printWriter);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"message\":\"Too many attempts\"}");

        try (MockedStatic<com.figrclub.figrclubdb.util.IpUtils> ipUtilsMock =
                     mockStatic(com.figrclub.figrclubdb.util.IpUtils.class)) {

            ipUtilsMock.when(() -> com.figrclub.figrclubdb.util.IpUtils.getClientIpAddress(request))
                    .thenReturn("192.168.1.100");

            // Act
            rateLimitingFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(response).setStatus(429); // HTTP 429 Too Many Requests
            verify(response).setContentType("application/json");
            verify(response).setHeader("Retry-After", "1800"); // 30 minutes * 60 seconds
            verify(response).setHeader("X-RateLimit-Exceeded", "true");
            verify(response).setHeader("X-RateLimit-Block-Type", "IP_BLOCKED");
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void shouldNotFilter_StaticResources_ReturnsTrue() throws Exception {
        // Arrange
        when(request.getRequestURI()).thenReturn("/static/css/style.css");

        // Act
        boolean result = rateLimitingFilter.shouldNotFilter(request);

        // Assert
        assertTrue(result);
    }

    @Test
    void shouldNotFilter_ActuatorEndpoints_ReturnsTrue() throws Exception {
        // Arrange
        when(request.getRequestURI()).thenReturn("/actuator/health");

        // Act
        boolean result = rateLimitingFilter.shouldNotFilter(request);

        // Assert
        assertTrue(result);
    }

    @Test
    void shouldNotFilter_SwaggerEndpoints_ReturnsTrue() throws Exception {
        // Arrange
        when(request.getRequestURI()).thenReturn("/swagger-ui/index.html");

        // Act
        boolean result = rateLimitingFilter.shouldNotFilter(request);

        // Assert
        assertTrue(result);
    }

    @Test
    void shouldNotFilter_ApiEndpoints_ReturnsFalse() throws Exception {
        // Arrange
        when(request.getRequestURI()).thenReturn("/api/v1/auth/login");

        // Act
        boolean result = rateLimitingFilter.shouldNotFilter(request);

        // Assert
        assertFalse(result);
    }

    @Test
    void doFilterInternal_NullIp_HandlesGracefully() throws Exception {
        // Arrange
        when(request.getRequestURI()).thenReturn("/api/v1/auth/login");
        when(request.getMethod()).thenReturn("POST");

        try (MockedStatic<com.figrclub.figrclubdb.util.IpUtils> ipUtilsMock =
                     mockStatic(com.figrclub.figrclubdb.util.IpUtils.class)) {

            ipUtilsMock.when(() -> com.figrclub.figrclubdb.util.IpUtils.getClientIpAddress(request))
                    .thenReturn(null);

            // Act
            rateLimitingFilter.doFilterInternal(request, response, filterChain);

            // Assert
            // Debería continuar sin rate limiting ya que IP es null
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void doFilterInternal_NullWhitelistIps_HandlesGracefully() throws Exception {
        // Arrange
        ReflectionTestUtils.setField(rateLimitingFilter, "whitelistIps", null);
        when(request.getRequestURI()).thenReturn("/api/v1/auth/login");
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("email")).thenReturn("test@example.com");

        RateLimitInfo rateLimitInfo = RateLimitInfo.builder()
                .ipAddress("192.168.1.100")
                .email("test@example.com")
                .remainingIpAttempts(5)
                .remainingUserAttempts(3)
                .windowMinutes(15)
                .build();

        when(rateLimitingService.getRateLimitInfo(anyString(), anyString())).thenReturn(rateLimitInfo);
        doNothing().when(rateLimitingService).validateRateLimit(anyString(), anyString(), any(AttemptType.class));

        try (MockedStatic<com.figrclub.figrclubdb.util.IpUtils> ipUtilsMock =
                     mockStatic(com.figrclub.figrclubdb.util.IpUtils.class)) {

            ipUtilsMock.when(() -> com.figrclub.figrclubdb.util.IpUtils.getClientIpAddress(request))
                    .thenReturn("192.168.1.100");

            // Act
            rateLimitingFilter.doFilterInternal(request, response, filterChain);

            // Assert
            // Debería procesar normalmente ya que no está en whitelist (que es null)
            verify(rateLimitingService).validateRateLimit("192.168.1.100", "test@example.com", AttemptType.LOGIN);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void doFilterInternal_NullRequestURI_HandlesGracefully() throws Exception {
        // Arrange
        when(request.getRequestURI()).thenReturn(null);
        when(request.getMethod()).thenReturn("POST");

        try (MockedStatic<com.figrclub.figrclubdb.util.IpUtils> ipUtilsMock =
                     mockStatic(com.figrclub.figrclubdb.util.IpUtils.class)) {

            ipUtilsMock.when(() -> com.figrclub.figrclubdb.util.IpUtils.getClientIpAddress(request))
                    .thenReturn("192.168.1.100");

            // Act
            rateLimitingFilter.doFilterInternal(request, response, filterChain);

            // Assert
            // Debería continuar sin rate limiting ya que path es null
            verify(filterChain).doFilter(request, response);
        }
    }
}
