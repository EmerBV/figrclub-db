package com.figrclub.figrclubdb.controller;

import com.figrclub.figrclubdb.exceptions.PasswordException;
import com.figrclub.figrclubdb.exceptions.ResourceNotFoundException;
import com.figrclub.figrclubdb.request.PasswordChangeRequest;
import com.figrclub.figrclubdb.request.PasswordResetConfirmRequest;
import com.figrclub.figrclubdb.request.PasswordResetRequest;
import com.figrclub.figrclubdb.response.ApiResponse;
import com.figrclub.figrclubdb.service.password.IPasswordService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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

    @PostMapping("/change")
    @Operation(
            summary = "Change password",
            description = "Change password for authenticated user"
    )
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("isAuthenticated()")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password changed successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid request data or password validation failed"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "User not authenticated"
            )
    })
    public ResponseEntity<ApiResponse> changePassword(@Valid @RequestBody PasswordChangeRequest request) {
        try {
            log.info("Password change request received");
            passwordService.changePassword(request);
            return ResponseEntity.ok(new ApiResponse("Password changed successfully", null));
        } catch (PasswordException e) {
            log.warn("Password change failed: {}", e.getMessage());
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse(e.getMessage(), null));
        } catch (ResourceNotFoundException e) {
            log.error("User not found during password change: {}", e.getMessage());
            return ResponseEntity.status(UNAUTHORIZED)
                    .body(new ApiResponse("Authentication required", null));
        } catch (Exception e) {
            log.error("Unexpected error during password change", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("An unexpected error occurred", null));
        }
    }

    @PostMapping("/reset-request")
    @Operation(
            summary = "Request password reset",
            description = "Request a password reset token via email"
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password reset email sent (if email exists)"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid email format or too many requests"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "429",
                    description = "Too many password reset requests"
            )
    })
    public ResponseEntity<ApiResponse> requestPasswordReset(@Valid @RequestBody PasswordResetRequest request) {
        try {
            log.info("Password reset request received for email: {}", request.getEmail());
            passwordService.requestPasswordReset(request);
            // Siempre devolver el mismo mensaje por seguridad
            return ResponseEntity.ok(new ApiResponse(
                    "If the email exists in our system, you will receive a password reset link shortly",
                    null
            ));
        } catch (PasswordException e) {
            log.warn("Password reset request failed: {}", e.getMessage());
            return ResponseEntity.status(TOO_MANY_REQUESTS)
                    .body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Unexpected error during password reset request", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("An unexpected error occurred", null));
        }
    }

    @PostMapping("/reset-confirm")
    @Operation(
            summary = "Confirm password reset",
            description = "Reset password using the token received via email"
    )
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
    @Operation(
            summary = "Validate reset token",
            description = "Check if a password reset token is valid"
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Token validation result"
            )
    })
    public ResponseEntity<ApiResponse> validateResetToken(@RequestParam String token) {
        try {
            log.debug("Token validation request received");
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
    @Operation(
            summary = "Cleanup expired tokens",
            description = "Manually trigger cleanup of expired password reset tokens (Admin only)"
    )
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Token cleanup completed"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Access denied - Admin role required"
            )
    })
    public ResponseEntity<ApiResponse> cleanupExpiredTokens() {
        try {
            log.info("Manual token cleanup triggered");
            passwordService.cleanupExpiredTokens();
            return ResponseEntity.ok(new ApiResponse("Expired tokens cleaned up successfully", null));
        } catch (Exception e) {
            log.error("Error during manual token cleanup", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error during token cleanup", null));
        }
    }
}
