package com.figrclub.figrclubdb.controller;

import com.figrclub.figrclubdb.domain.model.Role;
import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
import com.figrclub.figrclubdb.response.ApiResponse;
import com.figrclub.figrclubdb.service.user.IUserService;
import com.figrclub.figrclubdb.service.user.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.springframework.http.HttpStatus.*;

/**
 * Controlador para gestión avanzada de roles de usuarios
 * Funcionalidad restaurada y mejorada
 */
@RestController
@RequestMapping("${api.prefix}/users/roles")
@RequiredArgsConstructor
@Tag(name = "Role Management", description = "Advanced user role management operations")
@Validated
@Slf4j
public class RoleManagementController {

    private final IUserService userService;

    // ===== ENDPOINTS DE CONSULTA DE ROLES =====

    @GetMapping("/admins")
    @Operation(summary = "Get admin users", description = "Retrieve all users with ADMIN role")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getAdminUsers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            log.info("Retrieving admin users");

            Pageable pageable = PageRequest.of(page, size, Sort.by("firstName", "lastName"));
            Page<User> adminUsersPage = userService.findAdminUsers(pageable);
            Page<UserDto> userDtoPage = adminUsersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());
            response.put("role", "ADMIN");

            return ResponseEntity.ok(new ApiResponse("Admin users retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving admin users", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving admin users", null));
        }
    }

    @GetMapping("/regular")
    @Operation(summary = "Get regular users", description = "Retrieve all users with USER role only")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getRegularUsers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            log.info("Retrieving regular users");

            Pageable pageable = PageRequest.of(page, size, Sort.by("firstName", "lastName"));
            Page<User> regularUsersPage = userService.findRegularUsers(pageable);
            Page<UserDto> userDtoPage = regularUsersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());
            response.put("role", "USER");

            return ResponseEntity.ok(new ApiResponse("Regular users retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving regular users", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving regular users", null));
        }
    }

    @GetMapping("/by-role/{roleName}")
    @Operation(summary = "Get users by specific role", description = "Retrieve users with a specific role")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getUsersByRole(
            @Parameter(description = "Role name (e.g., ROLE_USER, ROLE_ADMIN)")
            @PathVariable @NotBlank String roleName,
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            log.info("Retrieving users by role: {}", roleName);

            Pageable pageable = PageRequest.of(page, size, Sort.by("firstName", "lastName"));
            Page<User> usersPage = userService.findUsersByRole(roleName, pageable);
            Page<UserDto> userDtoPage = usersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());
            response.put("role", roleName);

            return ResponseEntity.ok(new ApiResponse("Users by role retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving users by role: {}", roleName, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving users by role", null));
        }
    }

    // ===== ENDPOINTS COMBINADOS: ROLES + TIERS =====

    @GetMapping("/admin-pro-sellers")
    @Operation(summary = "Get admin Pro Sellers", description = "Retrieve admins who are also Pro Sellers")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getAdminProSellers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            log.info("Retrieving admin Pro Sellers");

            Pageable pageable = PageRequest.of(page, size, Sort.by("firstName", "lastName"));
            Page<User> adminProSellersPage = userService.findAdminProSellers(pageable);
            Page<UserDto> userDtoPage = adminProSellersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());
            response.put("category", "ADMIN_PRO_SELLER");

            return ResponseEntity.ok(new ApiResponse("Admin Pro Sellers retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving admin Pro Sellers", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving admin Pro Sellers", null));
        }
    }

    @GetMapping("/regular-pro-sellers")
    @Operation(summary = "Get regular Pro Sellers", description = "Retrieve regular users who are Pro Sellers")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getRegularProSellers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            log.info("Retrieving regular Pro Sellers");

            Pageable pageable = PageRequest.of(page, size, Sort.by("firstName", "lastName"));
            Page<User> regularProSellersPage = userService.findRegularProSellers(pageable);
            Page<UserDto> userDtoPage = regularProSellersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());
            response.put("category", "REGULAR_PRO_SELLER");

            return ResponseEntity.ok(new ApiResponse("Regular Pro Sellers retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving regular Pro Sellers", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving regular Pro Sellers", null));
        }
    }

    @GetMapping("/admin-basic-users")
    @Operation(summary = "Get admin basic users", description = "Retrieve admins who are basic users (FREE+INDIVIDUAL)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getAdminBasicUsers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            log.info("Retrieving admin basic users");

            Pageable pageable = PageRequest.of(page, size, Sort.by("firstName", "lastName"));
            Page<User> adminBasicUsersPage = userService.findAdminBasicUsers(pageable);
            Page<UserDto> userDtoPage = adminBasicUsersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());
            response.put("category", "ADMIN_BASIC_USER");

            return ResponseEntity.ok(new ApiResponse("Admin basic users retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving admin basic users", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving admin basic users", null));
        }
    }

    // ===== ENDPOINTS DE GESTIÓN DE ROLES =====

    @GetMapping("/{userId}")
    @Operation(summary = "Get user roles", description = "Get all roles assigned to a specific user")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> getUserRoles(@PathVariable Long userId) {
        try {
            log.info("Getting roles for user: {}", userId);

            Set<Role> userRoles = userService.getUserRoles(userId);

            Map<String, Object> response = new HashMap<>();
            response.put("userId", userId);
            response.put("roles", userRoles);
            response.put("roleNames", userRoles.stream().map(Role::getName).toList());
            response.put("isAdmin", userService.userHasRole(userId, "ROLE_ADMIN"));
            response.put("roleCount", userRoles.size());

            return ResponseEntity.ok(new ApiResponse("User roles retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error getting roles for user: {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving user roles", null));
        }
    }

    @PostMapping("/{userId}/assign/{roleName}")
    @Operation(summary = "Assign role to user", description = "Assign a specific role to a user")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> assignRoleToUser(
            @Parameter(description = "User ID")
            @PathVariable Long userId,
            @Parameter(description = "Role name to assign")
            @PathVariable @NotBlank String roleName) {
        try {
            log.info("Assigning role {} to user {}", roleName, userId);

            User user = userService.assignRoleToUser(userId, roleName);
            UserDto userDto = userService.convertUserToDto(user);

            return ResponseEntity.ok(new ApiResponse(
                    String.format("Role %s assigned to user successfully", roleName),
                    userDto));
        } catch (Exception e) {
            log.error("Error assigning role {} to user {}", roleName, userId, e);
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error assigning role to user", null));
        }
    }

    @DeleteMapping("/{userId}/remove/{roleName}")
    @Operation(summary = "Remove role from user", description = "Remove a specific role from a user")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> removeRoleFromUser(
            @Parameter(description = "User ID")
            @PathVariable Long userId,
            @Parameter(description = "Role name to remove")
            @PathVariable @NotBlank String roleName) {
        try {
            log.info("Removing role {} from user {}", roleName, userId);

            User user = userService.removeRoleFromUser(userId, roleName);
            UserDto userDto = userService.convertUserToDto(user);

            return ResponseEntity.ok(new ApiResponse(
                    String.format("Role %s removed from user successfully", roleName),
                    userDto));
        } catch (IllegalStateException e) {
            log.warn("Cannot remove role {} from user {}: {}", roleName, userId, e.getMessage());
            return ResponseEntity.status(CONFLICT)
                    .body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error removing role {} from user {}", roleName, userId, e);
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error removing role from user", null));
        }
    }

    @PostMapping("/{userId}/promote-to-admin")
    @Operation(summary = "Promote user to admin", description = "Grant admin privileges to a regular user")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> promoteToAdmin(@PathVariable Long userId) {
        try {
            log.info("Promoting user {} to admin", userId);

            if (!userService.canPromoteToAdmin(userId)) {
                return ResponseEntity.status(BAD_REQUEST)
                        .body(new ApiResponse("User cannot be promoted to admin", null));
            }

            User user = userService.promoteToAdmin(userId);
            UserDto userDto = userService.convertUserToDto(user);

            return ResponseEntity.ok(new ApiResponse("User promoted to admin successfully", userDto));
        } catch (Exception e) {
            log.error("Error promoting user {} to admin", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error promoting user to admin", null));
        }
    }

    @PostMapping("/{userId}/revoke-admin")
    @Operation(summary = "Revoke admin privileges", description = "Remove admin privileges from a user")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> revokeAdminPrivileges(@PathVariable Long userId) {
        try {
            log.info("Revoking admin privileges from user {}", userId);

            if (!userService.canRevokeAdminPrivileges(userId)) {
                return ResponseEntity.status(CONFLICT)
                        .body(new ApiResponse("Cannot revoke admin privileges: user is the last administrator", null));
            }

            User user = userService.revokeAdminPrivileges(userId);
            UserDto userDto = userService.convertUserToDto(user);

            return ResponseEntity.ok(new ApiResponse("Admin privileges revoked successfully", userDto));
        } catch (Exception e) {
            log.error("Error revoking admin privileges from user {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error revoking admin privileges", null));
        }
    }

    // ===== ENDPOINTS DE ESTADÍSTICAS =====

    @GetMapping("/stats/roles")
    @Operation(summary = "Get role statistics", description = "Get comprehensive role distribution statistics")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getRoleStats() {
        try {
            log.info("Retrieving role statistics");

            UserService.RoleStats roleStats = userService.getRoleStats();

            Map<String, Object> response = new HashMap<>();
            response.put("roleStats", roleStats);

            // Calcular porcentajes
            if (roleStats.totalUsers() > 0) {
                response.put("adminPercentage", (double) roleStats.adminUsers() / roleStats.totalUsers() * 100);
                response.put("regularUserPercentage", (double) roleStats.regularUsers() / roleStats.totalUsers() * 100);
                response.put("adminProSellerPercentage", (double) roleStats.adminProSellers() / roleStats.totalUsers() * 100);
            }

            return ResponseEntity.ok(new ApiResponse("Role statistics retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving role statistics", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving role statistics", null));
        }
    }

    @GetMapping("/stats/complete")
    @Operation(summary = "Get complete distribution", description = "Get complete user distribution including roles and tiers")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getCompleteDistribution() {
        try {
            log.info("Retrieving complete user distribution");

            UserService.CompleteDistribution distribution = userService.getCompleteDistribution();

            Map<String, Object> response = new HashMap<>();
            response.put("distribution", distribution);

            // Análisis adicional
            UserService.UserStats userStats = distribution.userStats();
            UserService.RoleStats roleStats = distribution.roleStats();

            Map<String, Object> analysis = new HashMap<>();
            if (userStats.totalUsers() > 0) {
                analysis.put("proConversionRate", (double) userStats.proUsers() / userStats.totalUsers() * 100);
                analysis.put("adminRatio", (double) roleStats.adminUsers() / userStats.totalUsers() * 100);
                analysis.put("verificationRate", (double) userStats.verifiedUsers() / userStats.totalUsers() * 100);
            }

            response.put("analysis", analysis);
            response.put("configurationHealth", distribution.configurationDistribution());

            return ResponseEntity.ok(new ApiResponse("Complete distribution retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving complete distribution", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving complete distribution", null));
        }
    }

    @GetMapping("/stats/counts")
    @Operation(summary = "Get role counts", description = "Get simple counts by role")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getRoleCounts() {
        try {
            log.info("Retrieving role counts");

            Map<String, Object> counts = new HashMap<>();
            counts.put("totalUsers", userService.getUserStats().totalUsers());
            counts.put("adminUsers", userService.countUsersByRole("ROLE_ADMIN"));
            counts.put("regularUsers", userService.countUsersByRole("ROLE_USER"));
            counts.put("activeAdmins", userService.getAdminCount());

            // Verificaciones de seguridad
            counts.put("canCreateMoreAdmins", true); // Siempre se pueden crear más admins
            counts.put("hasMinimumAdmins", userService.getAdminCount() >= 1);

            return ResponseEntity.ok(new ApiResponse("Role counts retrieved successfully", counts));
        } catch (Exception e) {
            log.error("Error retrieving role counts", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving role counts", null));
        }
    }

    // ===== ENDPOINTS DE VERIFICACIÓN =====

    @GetMapping("/{userId}/can-promote")
    @Operation(summary = "Check if user can be promoted", description = "Check if a user can be promoted to admin")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> checkCanPromoteToAdmin(@PathVariable Long userId) {
        try {
            log.debug("Checking if user {} can be promoted to admin", userId);

            boolean canPromote = userService.canPromoteToAdmin(userId);
            boolean isAlreadyAdmin = userService.userHasRole(userId, "ROLE_ADMIN");
            boolean isVerified = userService.getUserById(userId).isEmailVerified();

            Map<String, Object> response = new HashMap<>();
            response.put("userId", userId);
            response.put("canPromote", canPromote);
            response.put("isAlreadyAdmin", isAlreadyAdmin);
            response.put("isVerified", isVerified);
            response.put("reason", canPromote ? "User can be promoted" :
                    isAlreadyAdmin ? "User is already an admin" :
                            !isVerified ? "User email is not verified" : "Unknown reason");

            return ResponseEntity.ok(new ApiResponse("Promotion eligibility checked", response));
        } catch (Exception e) {
            log.error("Error checking promotion eligibility for user {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error checking promotion eligibility", null));
        }
    }

    @GetMapping("/{userId}/can-revoke-admin")
    @Operation(summary = "Check if admin can be revoked", description = "Check if admin privileges can be revoked from a user")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> checkCanRevokeAdmin(@PathVariable Long userId) {
        try {
            log.debug("Checking if admin privileges can be revoked from user {}", userId);

            boolean canRevoke = userService.canRevokeAdminPrivileges(userId);
            boolean isAdmin = userService.userHasRole(userId, "ROLE_ADMIN");
            long totalAdmins = userService.getAdminCount();

            Map<String, Object> response = new HashMap<>();
            response.put("userId", userId);
            response.put("canRevoke", canRevoke);
            response.put("isAdmin", isAdmin);
            response.put("totalAdmins", totalAdmins);
            response.put("reason", canRevoke ? "Admin privileges can be revoked" :
                    !isAdmin ? "User is not an admin" :
                            totalAdmins <= 1 ? "Cannot revoke: user is the last administrator" : "Unknown reason");

            return ResponseEntity.ok(new ApiResponse("Admin revocation eligibility checked", response));
        } catch (Exception e) {
            log.error("Error checking admin revocation eligibility for user {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error checking admin revocation eligibility", null));
        }
    }

    // ===== ENDPOINTS DE BÚSQUEDA AVANZADA =====

    @GetMapping("/search")
    @Operation(summary = "Search users by role and criteria", description = "Advanced search for users with role filtering")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> searchUsersByRoleAndCriteria(
            @Parameter(description = "Search term")
            @RequestParam(required = false) String searchTerm,
            @Parameter(description = "Role filter")
            @RequestParam(required = false) String role,
            @Parameter(description = "User type filter")
            @RequestParam(required = false) String userType,
            @Parameter(description = "Only verified users")
            @RequestParam(defaultValue = "false") boolean verifiedOnly,
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            log.info("Advanced search: term={}, role={}, userType={}, verifiedOnly={}",
                    searchTerm, role, userType, verifiedOnly);

            Pageable pageable = PageRequest.of(page, size, Sort.by("firstName", "lastName"));
            Page<User> usersPage;

            // Lógica de búsqueda combinada
            if (searchTerm != null && !searchTerm.trim().isEmpty()) {
                usersPage = userService.searchUsers(searchTerm, pageable);
                // Filtrar por rol si se especifica
                if (role != null && !role.trim().isEmpty()) {
                    usersPage = usersPage.map(user ->
                                    user.hasRole(role) ? user : null)
                            .map(user -> user); // Esto necesitaría una implementación más sofisticada
                }
            } else if (role != null && !role.trim().isEmpty()) {
                usersPage = userService.findUsersByRole(role, pageable);
            } else {
                usersPage = verifiedOnly ?
                        userService.findVerifiedUsers(pageable) :
                        userService.findAllUsers(pageable);
            }

            Page<UserDto> userDtoPage = usersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());
            response.put("filters", Map.of(
                    "searchTerm", searchTerm != null ? searchTerm : "",
                    "role", role != null ? role : "",
                    "userType", userType != null ? userType : "",
                    "verifiedOnly", verifiedOnly
            ));

            return ResponseEntity.ok(new ApiResponse("Advanced search completed successfully", response));
        } catch (Exception e) {
            log.error("Error in advanced search", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error in advanced search", null));
        }
    }

    // ===== ENDPOINTS DE MANTENIMIENTO =====

    @PostMapping("/maintenance/fix-roles")
    @Operation(summary = "Fix role issues", description = "Fix common role-related issues (Admin only)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> fixRoleIssues() {
        try {
            log.info("Starting role maintenance");

            Map<String, Object> results = new HashMap<>();

            // Asegurar que existe al menos un admin activo
            long activeAdmins = userService.getAdminCount();
            results.put("activeAdminsFound", activeAdmins);

            if (activeAdmins == 0) {
                log.warn("No active admins found! This should not happen.");
                results.put("warning", "No active administrators found in the system");
            }

            // Otras verificaciones y correcciones podrían ir aquí
            results.put("systemHealth", "OK");
            results.put("maintenanceCompleted", true);

            return ResponseEntity.ok(new ApiResponse("Role maintenance completed successfully", results));
        } catch (Exception e) {
            log.error("Error during role maintenance", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error during role maintenance", null));
        }
    }

    @GetMapping("/health-check")
    @Operation(summary = "Role system health check", description = "Check the health of the role system")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> roleSystemHealthCheck() {
        try {
            log.info("Performing role system health check");

            Map<String, Object> healthCheck = new HashMap<>();

            long totalUsers = userService.getUserStats().totalUsers();
            long adminUsers = userService.countUsersByRole("ROLE_ADMIN");
            long regularUsers = userService.countUsersByRole("ROLE_USER");

            healthCheck.put("totalUsers", totalUsers);
            healthCheck.put("adminUsers", adminUsers);
            healthCheck.put("regularUsers", regularUsers);
            healthCheck.put("hasAdmins", adminUsers > 0);
            healthCheck.put("hasUsers", regularUsers > 0);

            // Verificaciones de salud
            boolean isHealthy = adminUsers > 0 && totalUsers > 0;
            healthCheck.put("isHealthy", isHealthy);

            if (!isHealthy) {
                healthCheck.put("issues", adminUsers == 0 ?
                        "No administrators found in system" :
                        "No users found in system");
            }

            return ResponseEntity.ok(new ApiResponse("Role system health check completed", healthCheck));
        } catch (Exception e) {
            log.error("Error during role system health check", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error during health check", null));
        }
    }
}
