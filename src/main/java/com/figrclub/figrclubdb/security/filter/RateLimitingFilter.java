package com.figrclub.figrclubdb.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.figrclub.figrclubdb.dto.RateLimitInfo;
import com.figrclub.figrclubdb.enums.AttemptType;
import com.figrclub.figrclubdb.exceptions.RateLimitExceededException;
import com.figrclub.figrclubdb.response.ApiResponse;
import com.figrclub.figrclubdb.service.ratelimit.IRateLimitingService;
import com.figrclub.figrclubdb.util.IpUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;
import java.util.HashSet;

@Component
@RequiredArgsConstructor
@Slf4j
public class RateLimitingFilter extends OncePerRequestFilter {

    private final IRateLimitingService rateLimitingService;
    private final ObjectMapper objectMapper;

    @Value("${app.security.rate-limit.enabled:true}")
    private boolean rateLimitingEnabled;

    @Value("${app.security.rate-limit.whitelist-ips:127.0.0.1,::1}")
    private Set<String> whitelistIps;

    // Rutas que requieren rate limiting más estricto
    private static final Set<String> PROTECTED_PATHS = Set.of(
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/password/reset-request",
            "/api/v1/password/reset-confirm",
            "/api/v1/password/change"
    );

    // Rutas que requieren rate limiting básico
    private static final Set<String> MONITORED_PATHS = Set.of(
            "/api/v1/users",
            "/api/v1/auth"
    );

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        if (!rateLimitingEnabled) {
            filterChain.doFilter(request, response);
            return;
        }

        String requestPath = request.getRequestURI();
        String method = request.getMethod();
        String clientIp = IpUtils.getClientIpAddress(request);

        // Skip rate limiting for whitelisted IPs
        if (isWhitelistedIp(clientIp)) {
            log.debug("Skipping rate limiting for whitelisted IP: {}", clientIp);
            filterChain.doFilter(request, response);
            return;
        }

        // Skip rate limiting for non-protected paths
        if (!requiresRateLimiting(requestPath, method)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            AttemptType attemptType = determineAttemptType(requestPath, method);
            String email = extractEmailFromRequest(request);

            // Verificar límites antes de procesar la solicitud
            rateLimitingService.validateRateLimit(clientIp, email, attemptType);

            // Agregar headers informativos sobre rate limiting
            addRateLimitHeaders(response, clientIp, email);

            // Continuar con la cadena de filtros
            filterChain.doFilter(request, response);

        } catch (RateLimitExceededException e) {
            handleRateLimitExceeded(request, response, e, clientIp);
        } catch (Exception e) {
            log.error("Error in rate limiting filter", e);
            // En caso de error, permitir que continúe la solicitud
            filterChain.doFilter(request, response);
        }
    }

    private boolean isWhitelistedIp(String ip) {
        // Validar que tanto la IP como whitelistIps no sean nulos
        if (ip == null || whitelistIps == null) {
            return false;
        }
        return whitelistIps.contains(ip);
    }

    private boolean requiresRateLimiting(String path, String method) {
        // Validaciones de null safety
        if (path == null || method == null) {
            return false;
        }

        // Solo aplicar rate limiting a métodos POST/PUT/PATCH
        if (!Set.of("POST", "PUT", "PATCH").contains(method)) {
            return false;
        }

        return PROTECTED_PATHS.stream().anyMatch(path::startsWith) ||
                MONITORED_PATHS.stream().anyMatch(path::startsWith);
    }

    private AttemptType determineAttemptType(String path, String method) {
        if (path == null) {
            return AttemptType.API_ACCESS;
        }

        if (path.contains("/auth/login")) {
            return AttemptType.LOGIN;
        } else if (path.contains("/auth/register")) {
            return AttemptType.REGISTRATION;
        } else if (path.contains("/password/reset-request")) {
            return AttemptType.PASSWORD_RESET;
        } else if (path.contains("/password/reset-confirm") || path.contains("/password/change")) {
            return AttemptType.PASSWORD_CHANGE;
        } else if (path.contains("/api/")) {
            return AttemptType.API_ACCESS;
        }
        return AttemptType.API_ACCESS;
    }

    private String extractEmailFromRequest(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        // Para solicitudes POST, intentar extraer email del cuerpo
        // Esto es una implementación simplificada
        String email = request.getParameter("email");
        if (email == null) {
            email = request.getHeader("X-User-Email");
        }
        return email;
    }

    private void addRateLimitHeaders(HttpServletResponse response, String clientIp, String email) {
        try {
            RateLimitInfo info = rateLimitingService.getRateLimitInfo(clientIp, email);

            response.setHeader("X-RateLimit-Limit-IP", String.valueOf(info.getRemainingIpAttempts() + info.getIpAttempts()));
            response.setHeader("X-RateLimit-Remaining-IP", String.valueOf(info.getRemainingIpAttempts()));
            response.setHeader("X-RateLimit-Window", String.valueOf(info.getWindowMinutes()));

            if (email != null) {
                response.setHeader("X-RateLimit-Limit-User", String.valueOf(info.getRemainingUserAttempts() + info.getUserAttempts()));
                response.setHeader("X-RateLimit-Remaining-User", String.valueOf(info.getRemainingUserAttempts()));
            }

            if (info.getEarliestUnblockTime() != null) {
                response.setHeader("X-RateLimit-Reset", info.getEarliestUnblockTime().toString());
            }

        } catch (Exception e) {
            log.debug("Error adding rate limit headers: {}", e.getMessage());
        }
    }

    private void handleRateLimitExceeded(HttpServletRequest request, HttpServletResponse response,
                                         RateLimitExceededException e, String clientIp) {
        try {
            log.warn("Rate limit exceeded: IP={}, BlockType={}, Message={}", clientIp, e.getBlockType(), e.getMessage());

            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setHeader("Retry-After", String.valueOf(e.getRetryAfterSeconds()));
            response.setHeader("X-RateLimit-Exceeded", "true");
            response.setHeader("X-RateLimit-Block-Type", e.getBlockType().toString());

            ApiResponse apiResponse = ApiResponse.builder()
                    .message(e.getMessage())
                    .status(HttpStatus.TOO_MANY_REQUESTS.value())
                    .build();

            response.getWriter().write(objectMapper.writeValueAsString(apiResponse));

        } catch (IOException ioException) {
            log.error("Error writing rate limit response", ioException);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        if (path == null) {
            return true;
        }

        // No filtrar recursos estáticos
        if (path.startsWith("/static/") ||
                path.startsWith("/css/") ||
                path.startsWith("/js/") ||
                path.startsWith("/images/") ||
                path.startsWith("/webjars/")) {
            return true;
        }

        // No filtrar endpoints de actuator
        if (path.startsWith("/actuator/")) {
            return true;
        }

        // No filtrar documentación Swagger
        if (path.startsWith("/swagger-ui/") ||
                path.startsWith("/v3/api-docs") ||
                path.equals("/swagger-ui.html")) {
            return true;
        }

        // No filtrar favicon
        if (path.equals("/favicon.ico")) {
            return true;
        }

        return false;
    }
}
