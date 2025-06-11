package com.figrclub.figrclubdb.controller;

import com.figrclub.figrclubdb.enums.AttemptType;
import com.figrclub.figrclubdb.exceptions.PasswordException;
import com.figrclub.figrclubdb.exceptions.RateLimitExceededException;
import com.figrclub.figrclubdb.exceptions.ResourceNotFoundException;
import com.figrclub.figrclubdb.request.PasswordChangeRequest;
import com.figrclub.figrclubdb.request.PasswordResetConfirmRequest;
import com.figrclub.figrclubdb.request.PasswordResetRequest;
import com.figrclub.figrclubdb.response.ApiResponse;
import com.figrclub.figrclubdb.service.password.IPasswordService;
import com.figrclub.figrclubdb.service.ratelimit.IRateLimitingService;
import com.figrclub.figrclubdb.util.IpUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import static org.springframework.http.HttpStatus.*;

@RestController
@RequestMapping("${api.prefix}/password")
@RequiredArgsConstructor
@Tag(name = "Password Management", description = "Operations for password management and reset")
@Slf4j
public class PasswordController {

    private final IPasswordService passwordService;
    private final IRateLimitingService rateLimitingService;

    @PostMapping("/change")
    @Operation(summary = "Change password", description = "Change password for authenticated user")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse> changePassword(
            @Valid @RequestBody PasswordChangeRequest request,
            HttpServletRequest httpRequest) {

        String clientIp = IpUtils.getClientIpAddress(httpRequest);

        try {
            // Validar rate limiting
            rateLimitingService.validateRateLimit(clientIp, null, AttemptType.PASSWORD_CHANGE);

            passwordService.changePassword(request);

            // Registrar cambio exitoso
            rateLimitingService.recordSuccessfulAttempt(clientIp, null, AttemptType.PASSWORD_CHANGE);

            log.info("Password changed successfully from IP: {}", clientIp);
            return ResponseEntity.ok(new ApiResponse("Password changed successfully", null));

        } catch (RateLimitExceededException e) {
            log.warn("Password change blocked by rate limiting: IP={}", clientIp);
            return ResponseEntity.status(TOO_MANY_REQUESTS)
                    .body(new ApiResponse(e.getMessage(), null));
        } catch (PasswordException e) {
            // Registrar intento fallido
            rateLimitingService.recordFailedAttempt(clientIp, null, AttemptType.PASSWORD_CHANGE);

            log.warn("Password change failed from IP: {}, reason: {}", clientIp, e.getMessage());
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse(e.getMessage(), null));
        } catch (ResourceNotFoundException e) {
            log.error("User not found during password change from IP: {}", clientIp);
            return ResponseEntity.status(UNAUTHORIZED)
                    .body(new ApiResponse("Authentication required", null));
        } catch (Exception e) {
            // Registrar intento fallido
            rateLimitingService.recordFailedAttempt(clientIp, null, AttemptType.PASSWORD_CHANGE);

            log.error("Unexpected error during password change from IP: {}", clientIp, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("An unexpected error occurred", null));
        }
    }

    @PostMapping("/reset-request")
    @Operation(summary = "Request password reset", description = "Request a password reset token via email")
    public ResponseEntity<ApiResponse> requestPasswordReset(
            @Valid @RequestBody PasswordResetRequest request,
            HttpServletRequest httpRequest) {

        String clientIp = IpUtils.getClientIpAddress(httpRequest);

        try {
            // Validar rate limiting
            rateLimitingService.validateRateLimit(clientIp, request.getEmail(), AttemptType.PASSWORD_RESET);

            passwordService.requestPasswordReset(request);

            // Registrar solicitud exitosa
            rateLimitingService.recordSuccessfulAttempt(clientIp, request.getEmail(), AttemptType.PASSWORD_RESET);

            log.info("Password reset requested from IP: {} for email: {}", clientIp, request.getEmail());
            return ResponseEntity.ok(new ApiResponse(
                    "If the email exists in our system, you will receive a password reset link shortly",
                    null
            ));

        } catch (RateLimitExceededException e) {
            log.warn("Password reset request blocked by rate limiting: IP={}, Email={}", clientIp, request.getEmail());
            return ResponseEntity.status(TOO_MANY_REQUESTS)
                    .body(new ApiResponse(e.getMessage(), null));
        } catch (PasswordException e) {
            // Registrar intento fallido
            rateLimitingService.recordFailedAttempt(clientIp, request.getEmail(), AttemptType.PASSWORD_RESET);

            log.warn("Password reset request failed from IP: {}, email: {}, reason: {}",
                    clientIp, request.getEmail(), e.getMessage());
            return ResponseEntity.status(TOO_MANY_REQUESTS)
                    .body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            // Registrar intento fallido
            rateLimitingService.recordFailedAttempt(clientIp, request.getEmail(), AttemptType.PASSWORD_RESET);

            log.error("Unexpected error during password reset request from IP: {}, email: {}",
                    clientIp, request.getEmail(), e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("An unexpected error occurred", null));
        }
    }

    @PostMapping("/reset-confirm")
    @Operation(summary = "Confirm password reset", description = "Reset password using the token received via email")
    public ResponseEntity<ApiResponse> confirmPasswordReset(
            @Valid @RequestBody PasswordResetConfirmRequest request,
            HttpServletRequest httpRequest) {

        String clientIp = IpUtils.getClientIpAddress(httpRequest);

        try {
            // Validar rate limiting (más restrictivo para confirmación)
            rateLimitingService.validateRateLimit(clientIp, null, AttemptType.PASSWORD_CHANGE);

            passwordService.confirmPasswordReset(request);

            // Registrar reset exitoso
            rateLimitingService.recordSuccessfulAttempt(clientIp, null, AttemptType.PASSWORD_CHANGE);

            log.info("Password reset confirmed successfully from IP: {}", clientIp);
            return ResponseEntity.ok(new ApiResponse("Password reset successfully", null));

        } catch (RateLimitExceededException e) {
            log.warn("Password reset confirmation blocked by rate limiting: IP={}", clientIp);
            return ResponseEntity.status(TOO_MANY_REQUESTS)
                    .body(new ApiResponse(e.getMessage(), null));
        } catch (PasswordException e) {
            // Registrar intento fallido
            rateLimitingService.recordFailedAttempt(clientIp, null, AttemptType.PASSWORD_CHANGE);

            log.warn("Password reset confirmation failed from IP: {}, reason: {}", clientIp, e.getMessage());
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            // Registrar intento fallido
            rateLimitingService.recordFailedAttempt(clientIp, null, AttemptType.PASSWORD_CHANGE);

            log.error("Unexpected error during password reset confirmation from IP: {}", clientIp, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("An unexpected error occurred", null));
        }
    }
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password reset successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid or expired token, or password validation failed"
            )
    })
    public ResponseEntity<ApiResponse> confirmPasswordReset(@Valid @RequestBody PasswordResetConfirmRequest request) {
        try {
            log.info("Password reset confirmation received");
            passwordService.confirmPasswordReset(request);
            return ResponseEntity.ok(new ApiResponse("Password reset successfully", null));
        } catch (PasswordException e) {
            log.warn("Password reset confirmation failed: {}", e.getMessage());
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Unexpected error during password reset confirmation", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("An unexpected error occurred", null));
        }
    }

    @GetMapping("/validate-token")
    public ResponseEntity<ApiResponse> validateResetToken(@RequestParam String token) {
        try {
            boolean isValid = passwordService.isValidResetToken(token);
            return ResponseEntity.ok(new ApiResponse(
                    isValid ? "Token is valid" : "Token is invalid or expired",
                    isValid
            ));
        } catch (Exception e) {
            log.error("Error validating token", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error validating token", false));
        }
    }

    @PostMapping("/cleanup-tokens")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> cleanupExpiredTokens() {
        try {
            passwordService.cleanupExpiredTokens();
            return ResponseEntity.ok(new ApiResponse("Expired tokens cleaned up successfully", null));
        } catch (Exception e) {
            log.error("Error during manual token cleanup", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error during token cleanup", null));
        }
    }
}
