package com.figrclub.figrclubdb.controller;

import com.figrclub.figrclubdb.exceptions.TokenAlreadyUsedException;
import com.figrclub.figrclubdb.exceptions.TokenExpiredException;
import com.figrclub.figrclubdb.response.ApiResponse;
import com.figrclub.figrclubdb.service.email.EmailVerificationService;
import com.figrclub.figrclubdb.service.email.EmailVerificationService.VerificationStats;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.CompletableFuture;

/**
 * Controlador para verificación de email
 * Maneja endpoints relacionados con la verificación de correos electrónicos
 */
@RestController
@RequestMapping("${api.prefix}/email")
@RequiredArgsConstructor
@Validated
@Slf4j
@Tag(name = "Email Verification", description = "Endpoints para verificación de email")
public class EmailVerificationController {

    private final EmailVerificationService emailVerificationService;

    /**
     * Verifica un email usando el token proporcionado
     */
    @PostMapping("/verify")
    @Operation(
            summary = "Verificar email",
            description = "Verifica el email del usuario usando el token de verificación"
    )
    public ResponseEntity<ApiResponse> verifyEmail(
            @Parameter(description = "Token de verificación", required = true)
            @RequestParam @NotBlank(message = "Token is required") String token,
            HttpServletRequest request) {

        try {
            String ipAddress = getClientIpAddress(request);
            String userAgent = request.getHeader("User-Agent");

            log.info("Email verification attempt from IP: {}", ipAddress);

            boolean verified = emailVerificationService.verifyEmail(token, ipAddress, userAgent);

            if (verified) {
                return ResponseEntity.ok(
                        new ApiResponse("Email verificado exitosamente. ¡Bienvenido a FigrClub!", null)
                );
            } else {
                return ResponseEntity.badRequest()
                        .body(new ApiResponse("Token de verificación inválido", null));
            }

        } catch (TokenExpiredException e) {
            log.warn("Token expired during verification: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.GONE)
                    .body(new ApiResponse("El token de verificación ha expirado. Solicita uno nuevo.", null));

        } catch (TokenAlreadyUsedException e) {
            log.warn("Token already used during verification: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ApiResponse("El token de verificación ya fue utilizado.", null));

        } catch (Exception e) {
            log.error("Error during email verification: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error interno del servidor durante la verificación", null));
        }
    }

    /**
     * Reenvía el token de verificación
     */
    @PostMapping("/resend")
    @Operation(
            summary = "Reenviar token de verificación",
            description = "Reenvía el token de verificación al email especificado"
    )
    public ResponseEntity<ApiResponse> resendVerificationToken(
            @Parameter(description = "Email del usuario", required = true)
            @RequestParam @Email(message = "Email should be valid") @NotBlank(message = "Email is required") String email) {

        try {
            log.info("Resend verification token request for email: {}", email);

            // Verificar si ya está verificado
            if (emailVerificationService.isEmailVerified(email)) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(new ApiResponse("El email ya está verificado", null));
            }

            CompletableFuture<Boolean> result = emailVerificationService.resendVerificationToken(email);
            Boolean sent = result.get(); // Esperar resultado

            if (sent) {
                return ResponseEntity.ok(
                        new ApiResponse("Token de verificación reenviado exitosamente", null)
                );
            } else {
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .body(new ApiResponse("Demasiados intentos de reenvío. Intenta más tarde.", null));
            }

        } catch (Exception e) {
            log.error("Error resending verification token for {}: {}", email, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error al reenviar el token de verificación", null));
        }
    }

    /**
     * Obtiene el estado de verificación de un email
     */
    @GetMapping("/status")
    @Operation(
            summary = "Obtener estado de verificación",
            description = "Obtiene el estado de verificación de un email específico"
    )
    public ResponseEntity<ApiResponse> getVerificationStatus(
            @Parameter(description = "Email del usuario", required = true)
            @RequestParam @Email(message = "Email should be valid") @NotBlank(message = "Email is required") String email) {

        try {
            log.debug("Getting verification status for email: {}", email);

            VerificationStats stats = emailVerificationService.getVerificationStats(email);

            if (!stats.userExists()) {
                return ResponseEntity.notFound().build();
            }

            return ResponseEntity.ok(
                    new ApiResponse("Estado de verificación obtenido exitosamente", stats)
            );

        } catch (Exception e) {
            log.error("Error getting verification status for {}: {}", email, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error al obtener el estado de verificación", null));
        }
    }

    /**
     * Endpoint para verificar si un email está verificado (público)
     */
    @GetMapping("/check")
    @Operation(
            summary = "Verificar si email está verificado",
            description = "Verifica si un email específico ya está verificado"
    )
    public ResponseEntity<ApiResponse> checkEmailVerified(
            @Parameter(description = "Email a verificar", required = true)
            @RequestParam @Email(message = "Email should be valid") @NotBlank(message = "Email is required") String email) {

        try {
            log.debug("Checking if email is verified: {}", email);

            boolean isVerified = emailVerificationService.isEmailVerified(email);

            return ResponseEntity.ok(
                    new ApiResponse(
                            isVerified ? "Email está verificado" : "Email no está verificado",
                            new EmailVerificationStatus(email, isVerified)
                    )
            );

        } catch (Exception e) {
            log.error("Error checking email verification for {}: {}", email, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error al verificar el estado del email", null));
        }
    }

    /**
     * Obtiene la dirección IP real del cliente
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    /**
     * Record para respuesta de estado de verificación
     */
    public record EmailVerificationStatus(String email, boolean isVerified) {}
}
