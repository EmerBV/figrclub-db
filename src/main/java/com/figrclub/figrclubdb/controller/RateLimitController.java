package com.figrclub.figrclubdb.controller;

import com.figrclub.figrclubdb.domain.model.LoginAttempt;
import com.figrclub.figrclubdb.dto.RateLimitInfo;
import com.figrclub.figrclubdb.enums.AttemptType;
import com.figrclub.figrclubdb.request.BlockRequest;
import com.figrclub.figrclubdb.response.ApiResponse;
import com.figrclub.figrclubdb.service.ratelimit.IRateLimitingService;
import com.figrclub.figrclubdb.util.IpUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpStatus.*;

@RestController
@RequestMapping("${api.prefix}/rate-limit")
@RequiredArgsConstructor
@Tag(name = "Rate Limiting Management", description = "Operations for managing rate limiting and security")
@Slf4j
public class RateLimitController {

    private final IRateLimitingService rateLimitingService;

    @GetMapping("/status")
    @Operation(
            summary = "Get rate limit status",
            description = "Get current rate limiting status for the requesting IP/user"
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Rate limit status retrieved successfully"
            )
    })
    public ResponseEntity<ApiResponse> getRateLimitStatus(
            HttpServletRequest request,
            @Parameter(description = "Email to check (optional)")
            @RequestParam(required = false) String email) {

        try {
            String clientIp = IpUtils.getClientIpAddress(request);
            RateLimitInfo rateLimitInfo = rateLimitingService.getRateLimitInfo(clientIp, email);

            Map<String, Object> response = new HashMap<>();
            response.put("rateLimitInfo", rateLimitInfo);
            response.put("clientIp", clientIp);
            response.put("ipBlocked", rateLimitingService.isIpBlocked(clientIp));
            response.put("userBlocked", email != null ? rateLimitingService.isUserBlocked(email) : false);

            return ResponseEntity.ok(new ApiResponse("Rate limit status retrieved", response));

        } catch (Exception e) {
            log.error("Error retrieving rate limit status", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving rate limit status", null));
        }
    }

    @GetMapping("/admin/attempts")
    @Operation(
            summary = "Get recent login attempts",
            description = "Get recent login attempts for analysis (Admin only)"
    )
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Login attempts retrieved successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Access denied - Admin role required"
            )
    })
    public ResponseEntity<ApiResponse> getRecentAttempts(
            @Parameter(description = "IP address to filter (optional)")
            @RequestParam(required = false) String ipAddress,
            @Parameter(description = "Email to filter (optional)")
            @RequestParam(required = false) String email,
            @Parameter(description = "Hours to look back")
            @RequestParam(defaultValue = "24") int hours) {

        try {
            List<LoginAttempt> attempts = rateLimitingService.getRecentFailedAttempts(ipAddress, email, hours);

            Map<String, Object> response = new HashMap<>();
            response.put("attempts", attempts);
            response.put("count", attempts.size());
            response.put("hoursBack", hours);
            response.put("filters", Map.of("ipAddress", ipAddress, "email", email));

            return ResponseEntity.ok(new ApiResponse("Recent attempts retrieved", response));

        } catch (Exception e) {
            log.error("Error retrieving recent attempts", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving recent attempts", null));
        }
    }

    @PostMapping("/admin/block-ip")
    @Operation(
            summary = "Block IP address",
            description = "Manually block an IP address (Admin only)"
    )
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "IP blocked successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid request data"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Access denied - Admin role required"
            )
    })
    public ResponseEntity<ApiResponse> blockIp(@Valid @RequestBody BlockRequest request) {
        try {
            log.info("Admin blocking IP: {} for {} minutes. Reason: {}",
                    request.getIdentifier(), request.getDurationMinutes(), request.getReason());

            rateLimitingService.blockIpExplicitly(
                    request.getIdentifier(),
                    request.getDurationMinutes(),
                    request.getReason()
            );

            return ResponseEntity.ok(new ApiResponse("IP blocked successfully", null));

        } catch (Exception e) {
            log.error("Error blocking IP: {}", request.getIdentifier(), e);
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error blocking IP", null));
        }
    }

    @PostMapping("/admin/block-user")
    @Operation(
            summary = "Block user",
            description = "Manually block a user by email (Admin only)"
    )
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "User blocked successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid request data"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Access denied - Admin role required"
            )
    })
    public ResponseEntity<ApiResponse> blockUser(@Valid @RequestBody BlockRequest request) {
        try {
            log.info("Admin blocking user: {} for {} minutes. Reason: {}",
                    request.getIdentifier(), request.getDurationMinutes(), request.getReason());

            rateLimitingService.blockUserExplicitly(
                    request.getIdentifier(),
                    request.getDurationMinutes(),
                    request.getReason()
            );

            return ResponseEntity.ok(new ApiResponse("User blocked successfully", null));

        } catch (Exception e) {
            log.error("Error blocking user: {}", request.getIdentifier(), e);
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error blocking user", null));
        }
    }

    @DeleteMapping("/admin/unblock-ip/{ipAddress}")
    @Operation(
            summary = "Unblock IP address",
            description = "Manually unblock an IP address (Admin only)"
    )
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "IP unblocked successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Access denied - Admin role required"
            )
    })
    public ResponseEntity<ApiResponse> unblockIp(@PathVariable String ipAddress) {
        try {
            log.info("Admin unblocking IP: {}", ipAddress);
            rateLimitingService.unblockIp(ipAddress);

            return ResponseEntity.ok(new ApiResponse("IP unblocked successfully", null));

        } catch (Exception e) {
            log.error("Error unblocking IP: {}", ipAddress, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error unblocking IP", null));
        }
    }

    @DeleteMapping("/admin/unblock-user/{email}")
    @Operation(
            summary = "Unblock user",
            description = "Manually unblock a user by email (Admin only)"
    )
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "User unblocked successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Access denied - Admin role required"
            )
    })
    public ResponseEntity<ApiResponse> unblockUser(@PathVariable String email) {
        try {
            log.info("Admin unblocking user: {}", email);
            rateLimitingService.unblockUser(email);

            return ResponseEntity.ok(new ApiResponse("User unblocked successfully", null));

        } catch (Exception e) {
            log.error("Error unblocking user: {}", email, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error unblocking user", null));
        }
    }

    @PostMapping("/admin/cleanup")
    @Operation(
            summary = "Cleanup old attempts",
            description = "Manually trigger cleanup of old login attempts (Admin only)"
    )
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Cleanup completed successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Access denied - Admin role required"
            )
    })
    public ResponseEntity<ApiResponse> cleanupOldAttempts() {
        try {
            log.info("Admin triggered manual cleanup of old login attempts");
            rateLimitingService.cleanupOldAttempts();

            return ResponseEntity.ok(new ApiResponse("Cleanup completed successfully", null));

        } catch (Exception e) {
            log.error("Error during manual cleanup", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error during cleanup", null));
        }
    }

    @PostMapping("/admin/clear-failed/{email}")
    @Operation(
            summary = "Clear failed attempts for user",
            description = "Clear failed login attempts for a specific user (Admin only)"
    )
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Failed attempts cleared successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Access denied - Admin role required"
            )
    })
    public ResponseEntity<ApiResponse> clearFailedAttempts(@PathVariable String email) {
        try {
            log.info("Admin clearing failed attempts for user: {}", email);
            rateLimitingService.clearFailedAttemptsForUser(email);

            return ResponseEntity.ok(new ApiResponse("Failed attempts cleared successfully", null));

        } catch (Exception e) {
            log.error("Error clearing failed attempts for user: {}", email, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error clearing failed attempts", null));
        }
    }

    @PostMapping("/admin/clear-failed-ip/{ipAddress}")
    @Operation(
            summary = "Clear failed attempts for IP",
            description = "Clear failed login attempts for a specific IP (Admin only)"
    )
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Failed attempts cleared successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Access denied - Admin role required"
            )
    })
    public ResponseEntity<ApiResponse> clearFailedAttemptsForIp(@PathVariable String ipAddress) {
        try {
            log.info("Admin clearing failed attempts for IP: {}", ipAddress);
            rateLimitingService.clearFailedAttemptsForIp(ipAddress);

            return ResponseEntity.ok(new ApiResponse("Failed attempts cleared successfully", null));

        } catch (Exception e) {
            log.error("Error clearing failed attempts for IP: {}", ipAddress, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error clearing failed attempts", null));
        }
    }

    @GetMapping("/admin/check-status")
    @Operation(
            summary = "Check detailed status",
            description = "Check detailed rate limiting status for any IP/user (Admin only)"
    )
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Status retrieved successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Access denied - Admin role required"
            )
    })
    public ResponseEntity<ApiResponse> checkDetailedStatus(
            @Parameter(description = "IP address to check")
            @RequestParam(required = false) String ipAddress,
            @Parameter(description = "Email to check")
            @RequestParam(required = false) String email) {

        try {
            Map<String, Object> response = new HashMap<>();

            if (ipAddress != null) {
                response.put("ipBlocked", rateLimitingService.isIpBlocked(ipAddress));
                response.put("ipRateLimitInfo", rateLimitingService.getRateLimitInfo(ipAddress, null));
            }

            if (email != null) {
                response.put("userBlocked", rateLimitingService.isUserBlocked(email));
                response.put("userRateLimitInfo", rateLimitingService.getRateLimitInfo(null, email));
            }

            if (ipAddress != null && email != null) {
                response.put("combinedRateLimitInfo", rateLimitingService.getRateLimitInfo(ipAddress, email));
            }

            return ResponseEntity.ok(new ApiResponse("Detailed status retrieved", response));

        } catch (Exception e) {
            log.error("Error retrieving detailed status", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving detailed status", null));
        }
    }
}

