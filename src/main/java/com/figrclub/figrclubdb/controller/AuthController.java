package com.figrclub.figrclubdb.controller;

import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.request.CreateUserRequest;
import com.figrclub.figrclubdb.request.LoginRequest;
import com.figrclub.figrclubdb.response.ApiResponse;
import com.figrclub.figrclubdb.response.JwtResponse;
import com.figrclub.figrclubdb.security.jwt.JwtUtils;
import com.figrclub.figrclubdb.security.user.AppUserDetails;
import com.figrclub.figrclubdb.service.user.IUserService;
import com.figrclub.figrclubdb.service.email.EmailVerificationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.CompletableFuture;

/**
 * Controlador de autenticación con verificación de email integrada
 */
@RestController
@RequestMapping("${api.prefix}/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "Endpoints de autenticación y registro")
public class AuthController {

    private final IUserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final EmailVerificationService emailVerificationService;

    /**
     * Registro de usuario con verificación de email automática
     */
    @PostMapping("/register")
    @Operation(
            summary = "Registrar usuario",
            description = "Registra un nuevo usuario y envía email de verificación automáticamente"
    )
    public ResponseEntity<ApiResponse> register(@Valid @RequestBody CreateUserRequest request) {
        try {
            log.info("User registration attempt for email: {}", request.getEmail());

            // Crear usuario (inicialmente deshabilitado para verificación)
            User user = userService.createUser(request);

            // Enviar email de verificación automáticamente
            CompletableFuture<Boolean> emailSent = emailVerificationService.generateAndSendVerificationToken(user);

            // Preparar respuesta
            String message = "Usuario registrado exitosamente. ";

            try {
                Boolean sent = emailSent.get(); // Esperar resultado del email
                if (sent) {
                    message += "Se ha enviado un email de verificación a " + user.getEmail();
                } else {
                    message += "Error al enviar email de verificación. Puedes solicitar un reenvío.";
                    log.warn("Failed to send verification email for user: {}", user.getEmail());
                }
            } catch (Exception e) {
                message += "Error al enviar email de verificación. Puedes solicitar un reenvío.";
                log.error("Error waiting for email result for user {}: {}", user.getEmail(), e.getMessage());
            }

            RegisterResponse response = new RegisterResponse(
                    user.getId(),
                    user.getEmail(),
                    user.getFirstName() + " " + user.getLastName(),
                    user.isEnabled()
            );

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(new ApiResponse(message, response));

        } catch (Exception e) {
            log.error("Registration failed for email {}: {}", request.getEmail(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse("Registro fallido: " + e.getMessage(), null));
        }
    }

    /**
     * Login con verificación de estado de verificación de email
     */
    @PostMapping("/login")
    @Operation(
            summary = "Iniciar sesión",
            description = "Autentica usuario. Requiere email verificado para acceso completo."
    )
    public ResponseEntity<ApiResponse> login(@Valid @RequestBody LoginRequest request) {
        try {
            log.info("Login attempt for email: {}", request.getEmail());

            // Verificar si el email está verificado antes de autenticar
            if (!emailVerificationService.isEmailVerified(request.getEmail())) {
                log.warn("Login attempt with unverified email: {}", request.getEmail());
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(new ApiResponse("Email no verificado. Por favor verifica tu email antes de continuar.",
                                new UnverifiedEmailResponse(request.getEmail())));
            }

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateTokenForUser(authentication);
            AppUserDetails userDetails = (AppUserDetails) authentication.getPrincipal();

            JwtResponse jwtResponse = new JwtResponse(userDetails.getId(), jwt);

            log.info("Successful login for user: {}", request.getEmail());
            return ResponseEntity.ok(new ApiResponse("Login exitoso", jwtResponse));

        } catch (DisabledException e) {
            log.warn("Login attempt with disabled account: {}", request.getEmail());
            return ResponseEntity.status(HttpStatus.LOCKED)
                    .body(new ApiResponse("Cuenta deshabilitada. Contacta al administrador.", null));

        } catch (AuthenticationException e) {
            log.warn("Invalid login attempt for email: {}", request.getEmail());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse("Email o contraseña incorrectos", null));

        } catch (Exception e) {
            log.error("Login error for email {}: {}", request.getEmail(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error interno del servidor", null));
        }
    }

    /**
     * Endpoint para reenviar verificación desde el proceso de login
     */
    @PostMapping("/resend-verification")
    @Operation(
            summary = "Reenviar verificación desde login",
            description = "Reenvía email de verificación cuando el usuario intenta hacer login sin verificar"
    )
    public ResponseEntity<ApiResponse> resendVerificationFromLogin(@RequestParam String email) {
        try {
            log.info("Resend verification request from login for: {}", email);

            if (emailVerificationService.isEmailVerified(email)) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(new ApiResponse("El email ya está verificado. Puedes hacer login.", null));
            }

            CompletableFuture<Boolean> result = emailVerificationService.resendVerificationToken(email);
            Boolean sent = result.get();

            if (sent) {
                return ResponseEntity.ok(
                        new ApiResponse("Email de verificación reenviado exitosamente", null)
                );
            } else {
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .body(new ApiResponse("Demasiados intentos. Intenta más tarde.", null));
            }

        } catch (Exception e) {
            log.error("Error resending verification from login for {}: {}", email, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error al reenviar verificación", null));
        }
    }

    /**
     * Endpoint de estado de autenticación (para debugging)
     */
    @GetMapping("/status")
    @Operation(
            summary = "Estado de autenticación",
            description = "Obtiene el estado actual de autenticación (solo para desarrollo)"
    )
    public ResponseEntity<ApiResponse> getAuthStatus() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();

            if (auth != null && auth.isAuthenticated() && !auth.getName().equals("anonymousUser")) {
                AppUserDetails userDetails = (AppUserDetails) auth.getPrincipal();
                AuthStatusResponse status = new AuthStatusResponse(
                        true,
                        userDetails.getUsername(),
                        userDetails.getId(),
                        userDetails.getAuthorities().toString()
                );
                return ResponseEntity.ok(new ApiResponse("Usuario autenticado", status));
            } else {
                AuthStatusResponse status = new AuthStatusResponse(false, null, null, null);
                return ResponseEntity.ok(new ApiResponse("Usuario no autenticado", status));
            }

        } catch (Exception e) {
            log.error("Error getting auth status: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error al obtener estado de autenticación", null));
        }
    }

    /**
     * Logout del usuario
     */
    @PostMapping("/logout")
    @Operation(
            summary = "Cerrar sesión",
            description = "Cierra la sesión del usuario autenticado e invalida el token JWT."
    )
    public ResponseEntity<ApiResponse> logout(HttpServletRequest request) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();

            if (auth != null && auth.isAuthenticated() && !auth.getName().equals("anonymousUser")) {
                String userEmail = auth.getName();

                // Extraer y invalidar el token JWT
                String token = jwtUtils.extractTokenFromRequest(request);
                if (token != null) {
                    jwtUtils.invalidateToken(token);
                    log.info("User logout with token invalidation: {}", userEmail);
                } else {
                    log.info("User logout without token: {}", userEmail);
                }

                // Limpiar el contexto de seguridad
                SecurityContextHolder.clearContext();

                return ResponseEntity.ok(
                        new ApiResponse("Logout exitoso. Token invalidado.",
                                new LogoutResponse(userEmail, "SUCCESS"))
                );
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ApiResponse("No hay sesión activa para cerrar", null));
            }

        } catch (Exception e) {
            log.error("Error during logout: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error durante el logout", null));
        }
    }

    /**
     * Records para respuestas estructuradas
     */
    public record RegisterResponse(Long userId, String email, String fullName, boolean emailVerified) {}
    public record UnverifiedEmailResponse(String email) {}
    public record AuthStatusResponse(boolean authenticated, String email, Long userId, String authorities) {}
    public record LogoutResponse(String email, String status) {}
}
