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
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

/**
 * Controlador para verificación de email SIN FRONTEND
 * Maneja endpoints con respuestas HTML directas
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
     * Verifica un email usando GET - ESTE ES EL QUE VA EN EL EMAIL
     */
    @GetMapping("/verify")
    @Operation(
            summary = "Verificar email (GET)",
            description = "Verifica el email del usuario usando el token de verificación - responde con HTML"
    )
    public void verifyEmailDirect(
            @Parameter(description = "Token de verificación", required = true)
            @RequestParam @NotBlank(message = "Token is required") String token,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        try {
            String ipAddress = getClientIpAddress(request);
            String userAgent = request.getHeader("User-Agent");

            log.info("Direct email verification attempt from IP: {}", ipAddress);

            boolean verified = emailVerificationService.verifyEmail(token, ipAddress, userAgent);

            if (verified) {
                // Respuesta HTML de éxito
                response.setContentType("text/html; charset=UTF-8");
                response.setStatus(HttpServletResponse.SC_OK);
                response.getWriter().write(generateSuccessHtml());
            } else {
                // Respuesta HTML de error
                response.setContentType("text/html; charset=UTF-8");
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write(generateErrorHtml("Token de verificación inválido"));
            }

        } catch (TokenExpiredException e) {
            log.warn("Token expired during verification: {}", e.getMessage());
            response.setContentType("text/html; charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_GONE);
            response.getWriter().write(generateExpiredTokenHtml());

        } catch (TokenAlreadyUsedException e) {
            log.warn("Token already used during verification: {}", e.getMessage());
            response.setContentType("text/html; charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_CONFLICT);
            response.getWriter().write(generateAlreadyUsedHtml());

        } catch (Exception e) {
            log.error("Error during email verification: {}", e.getMessage(), e);
            response.setContentType("text/html; charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write(generateErrorHtml("Error interno del servidor"));
        }
    }

    /**
     * Endpoint alternativo que mantiene la funcionalidad POST para APIs
     */
    @PostMapping("/verify")
    @Operation(
            summary = "Verificar email (POST)",
            description = "Verifica el email del usuario usando el token de verificación - responde con JSON"
    )
    public ResponseEntity<ApiResponse> verifyEmailJson(
            @Parameter(description = "Token de verificación", required = true)
            @RequestParam @NotBlank(message = "Token is required") String token,
            HttpServletRequest request) {

        try {
            String ipAddress = getClientIpAddress(request);
            String userAgent = request.getHeader("User-Agent");

            log.info("JSON email verification attempt from IP: {}", ipAddress);

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

            if (emailVerificationService.isEmailVerified(email)) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(new ApiResponse("El email ya está verificado", null));
            }

            CompletableFuture<Boolean> result = emailVerificationService.resendVerificationToken(email);
            Boolean sent = result.get();

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

    // ===== MÉTODOS PRIVADOS PARA GENERAR HTML =====

    private String generateSuccessHtml() {
        return """
                <!DOCTYPE html>
                <html lang="es">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Email Verificado - FigrClub</title>
                    <style>
                        * { margin: 0; padding: 0; box-sizing: border-box; }
                        body { 
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            min-height: 100vh;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            padding: 20px;
                        }
                        .container {
                            background: white;
                            padding: 40px;
                            border-radius: 16px;
                            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                            text-align: center;
                            max-width: 500px;
                            width: 100%;
                        }
                        .success-icon {
                            width: 80px;
                            height: 80px;
                            background: #4CAF50;
                            border-radius: 50%;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            margin: 0 auto 30px;
                            font-size: 40px;
                            color: white;
                        }
                        h1 { 
                            color: #2c3e50; 
                            margin-bottom: 20px;
                            font-size: 28px;
                            font-weight: 600;
                        }
                        p { 
                            color: #666; 
                            line-height: 1.6;
                            margin-bottom: 15px;
                            font-size: 16px;
                        }
                        .brand {
                            color: #3498db;
                            font-weight: 600;
                        }
                        .footer {
                            margin-top: 30px;
                            padding-top: 20px;
                            border-top: 1px solid #eee;
                            font-size: 14px;
                            color: #999;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="success-icon">✓</div>
                        <h1>¡Email Verificado!</h1>
                        <p>Tu cuenta de <span class="brand">FigrClub</span> ha sido verificada exitosamente.</p>
                        <p>Ya puedes cerrar esta ventana y comenzar a usar todos nuestros servicios.</p>
                        <div class="footer">
                            <p>Gracias por unirte a FigrClub</p>
                        </div>
                    </div>
                </body>
                </html>
                """;
    }

    private String generateErrorHtml(String errorMessage) {
        return """
                <!DOCTYPE html>
                <html lang="es">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Error de Verificación - FigrClub</title>
                    <style>
                        * { margin: 0; padding: 0; box-sizing: border-box; }
                        body { 
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
                            min-height: 100vh;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            padding: 20px;
                        }
                        .container {
                            background: white;
                            padding: 40px;
                            border-radius: 16px;
                            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                            text-align: center;
                            max-width: 500px;
                            width: 100%;
                        }
                        .error-icon {
                            width: 80px;
                            height: 80px;
                            background: #e74c3c;
                            border-radius: 50%;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            margin: 0 auto 30px;
                            font-size: 40px;
                            color: white;
                        }
                        h1 { 
                            color: #2c3e50; 
                            margin-bottom: 20px;
                            font-size: 28px;
                            font-weight: 600;
                        }
                        p { 
                            color: #666; 
                            line-height: 1.6;
                            margin-bottom: 15px;
                            font-size: 16px;
                        }
                        .error-msg {
                            color: #e74c3c;
                            font-weight: 500;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="error-icon">✗</div>
                        <h1>Error de Verificación</h1>
                        <p class="error-msg">%s</p>
                        <p>Por favor, contacta al soporte si el problema persiste.</p>
                    </div>
                </body>
                </html>
                """.formatted(errorMessage);
    }

    private String generateExpiredTokenHtml() {
        return """
                <!DOCTYPE html>
                <html lang="es">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Token Expirado - FigrClub</title>
                    <style>
                        * { margin: 0; padding: 0; box-sizing: border-box; }
                        body { 
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                            background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);
                            min-height: 100vh;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            padding: 20px;
                        }
                        .container {
                            background: white;
                            padding: 40px;
                            border-radius: 16px;
                            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                            text-align: center;
                            max-width: 500px;
                            width: 100%;
                        }
                        .warning-icon {
                            width: 80px;
                            height: 80px;
                            background: #f39c12;
                            border-radius: 50%;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            margin: 0 auto 30px;
                            font-size: 40px;
                            color: white;
                        }
                        h1 { 
                            color: #2c3e50; 
                            margin-bottom: 20px;
                            font-size: 28px;
                            font-weight: 600;
                        }
                        p { 
                            color: #666; 
                            line-height: 1.6;
                            margin-bottom: 15px;
                            font-size: 16px;
                        }
                        .resend-info {
                            background: #fff3cd;
                            padding: 20px;
                            border-radius: 8px;
                            margin-top: 20px;
                            color: #856404;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="warning-icon">⚠</div>
                        <h1>Token Expirado</h1>
                        <p>El enlace de verificación ha expirado.</p>
                        <div class="resend-info">
                            <p><strong>¿Qué puedes hacer?</strong></p>
                            <p>Intenta hacer login nuevamente y solicita un nuevo enlace de verificación.</p>
                        </div>
                    </div>
                </body>
                </html>
                """;
    }

    private String generateAlreadyUsedHtml() {
        return """
                <!DOCTYPE html>
                <html lang="es">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Token Ya Utilizado - FigrClub</title>
                    <style>
                        * { margin: 0; padding: 0; box-sizing: border-box; }
                        body { 
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
                            min-height: 100vh;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            padding: 20px;
                        }
                        .container {
                            background: white;
                            padding: 40px;
                            border-radius: 16px;
                            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                            text-align: center;
                            max-width: 500px;
                            width: 100%;
                        }
                        .info-icon {
                            width: 80px;
                            height: 80px;
                            background: #3498db;
                            border-radius: 50%;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            margin: 0 auto 30px;
                            font-size: 40px;
                            color: white;
                        }
                        h1 { 
                            color: #2c3e50; 
                            margin-bottom: 20px;
                            font-size: 28px;
                            font-weight: 600;
                        }
                        p { 
                            color: #666; 
                            line-height: 1.6;
                            margin-bottom: 15px;
                            font-size: 16px;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="info-icon">ℹ</div>
                        <h1>Token Ya Utilizado</h1>
                        <p>Este enlace de verificación ya fue utilizado anteriormente.</p>
                        <p>Si tu cuenta ya está verificada, puedes proceder a hacer login normalmente.</p>
                    </div>
                </body>
                </html>
                """;
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
