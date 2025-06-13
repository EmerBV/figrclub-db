package com.figrclub.figrclubdb.controller;

import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.enums.UserType;
import com.figrclub.figrclubdb.exceptions.AlreadyExistsException;
import com.figrclub.figrclubdb.exceptions.ResourceNotFoundException;
import com.figrclub.figrclubdb.request.*;
import com.figrclub.figrclubdb.response.ApiResponse;
import com.figrclub.figrclubdb.service.user.IUserService;
import com.figrclub.figrclubdb.service.user.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.springframework.http.HttpStatus.*;

/**
 * Controlador de usuarios CORREGIDO con funcionalidad completa de roles y tiers
 */
@RequiredArgsConstructor
@RestController
@RequestMapping("${api.prefix}/users")
@Tag(name = "User Management", description = "Complete user management with roles and subscription tiers")
@Validated
@Slf4j
public class UserController {

    private final IUserService userService;

    // ===== ENDPOINTS BÁSICOS DE USUARIOS =====

    @GetMapping("/{userId}")
    @Operation(summary = "Get user by ID", description = "Retrieve a user by their unique identifier")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> getUserById(
            @Parameter(description = "User ID", required = true)
            @PathVariable Long userId) {
        try {
            log.info("Fetching user with ID: {}", userId);
            User user = userService.getUserById(userId);
            UserDto userDto = userService.convertUserToDto(user);

            // Información adicional sobre roles
            Map<String, Object> response = new HashMap<>();
            response.put("user", userDto);
            response.put("roleInfo", Map.of(
                    "isAdmin", user.isAdmin(),
                    "roles", user.getRoles().stream().map(role -> role.getName()).toList(),
                    "canPromoteToAdmin", !user.isAdmin() && userService.canPromoteToAdmin(userId),
                    "canRevokeAdmin", user.isAdmin() && userService.canRevokeAdminPrivileges(userId)
            ));

            return ResponseEntity.ok(new ApiResponse("User retrieved successfully", response));
        } catch (ResourceNotFoundException e) {
            log.warn("User not found with ID: {}", userId);
            return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error fetching user with ID: {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving user", null));
        }
    }

    @GetMapping
    @Operation(summary = "Get all users", description = "Retrieve all users with advanced filtering by roles and tiers")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getAllUsers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size,
            @Parameter(description = "Sort field")
            @RequestParam(defaultValue = "id") String sortBy,
            @Parameter(description = "Sort direction")
            @RequestParam(defaultValue = "asc") String sortDirection,
            @Parameter(description = "Filter by subscription type")
            @RequestParam(required = false) SubscriptionType subscriptionType,
            @Parameter(description = "Filter by user type")
            @RequestParam(required = false) UserType userType,
            @Parameter(description = "Filter by role")
            @RequestParam(required = false) String role,
            @Parameter(description = "Show only active users")
            @RequestParam(defaultValue = "true") boolean activeOnly) {

        try {
            Sort.Direction direction = sortDirection.equalsIgnoreCase("desc")
                    ? Sort.Direction.DESC : Sort.Direction.ASC;
            Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortBy));

            Page<User> usersPage;

            // LÓGICA DE FILTRADO MEJORADA CON ROLES
            if (role != null && !role.trim().isEmpty()) {
                // Filtrar por rol específico
                usersPage = userService.findUsersByRole(role, pageable);
            } else if (subscriptionType != null && userType != null) {
                // Filtro combinado - usar método de búsqueda básica
                usersPage = activeOnly
                        ? userService.findActiveUsers(pageable)
                        : userService.findAllUsers(pageable);
                // TODO: Implementar filtrado específico por combinación
            } else if (subscriptionType != null) {
                usersPage = subscriptionType == SubscriptionType.PRO
                        ? userService.findProUsers(pageable)
                        : userService.findFreeUsers(pageable);
            } else if (userType != null) {
                usersPage = userType == UserType.PRO_SELLER
                        ? userService.findProSellers(pageable)
                        : userService.findIndividualUsers(pageable);
            } else {
                usersPage = activeOnly
                        ? userService.findActiveUsers(pageable)
                        : userService.findAllUsers(pageable);
            }

            Page<UserDto> userDtoPage = usersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());
            response.put("filters", Map.of(
                    "subscriptionType", subscriptionType,
                    "userType", userType,
                    "role", role != null ? role : "",
                    "activeOnly", activeOnly
            ));

            // Información adicional de distribución
            UserService.UserStats stats = userService.getUserStats();
            response.put("summary", Map.of(
                    "totalUsers", stats.totalUsers(),
                    "adminUsers", stats.adminUsers(),
                    "regularUsers", stats.regularUsers(),
                    "proUsers", stats.proUsers(),
                    "freeUsers", stats.freeUsers()
            ));

            return ResponseEntity.ok(new ApiResponse("Users retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving users", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving users", null));
        }
    }

    @GetMapping("/me")
    @Operation(summary = "Get current user", description = "Retrieve the currently authenticated user with role information")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> getCurrentUser() {
        try {
            User user = userService.getAuthenticatedUser();
            UserDto userDto = userService.convertUserToDto(user);

            // Información adicional sobre el usuario actual
            Map<String, Object> response = new HashMap<>();
            response.put("user", userDto);
            response.put("permissions", Map.of(
                    "isAdmin", user.isAdmin(),
                    "canAccessAdminPanel", user.isAdmin(),
                    "canManageUsers", user.isAdmin(),
                    "canUpgradeToProSeller", userService.canUpgradeToProSeller(user.getId()),
                    "canAccessProFeatures", user.canAccessProFeatures()
            ));
            response.put("accountInfo", Map.of(
                    "tier", user.getSubscriptionType() + "+" + user.getUserType(),
                    "isValidConfiguration", user.isValidUserConfiguration(),
                    "emailVerified", user.isEmailVerified(),
                    "accountStatus", user.isAccountFullyActive() ? "ACTIVE" : "INACTIVE"
            ));

            return ResponseEntity.ok(new ApiResponse("Current user retrieved successfully", response));
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(UNAUTHORIZED).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error getting current user", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving current user", null));
        }
    }

    // ===== ENDPOINTS DE CREACIÓN MEJORADOS =====

    @PostMapping("/admin/add")
    @Operation(summary = "Create user (Admin only)", description = "Admin creates a user with optional role assignment")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> adminCreateUser(
            @Valid @RequestBody CreateUserRequest request,
            @Parameter(description = "Assign admin role")
            @RequestParam(defaultValue = "false") boolean makeAdmin,
            @Parameter(description = "Create pre-verified")
            @RequestParam(defaultValue = "true") boolean preVerified) {
        try {
            log.info("Admin creating user with email: {} (admin: {}, verified: {})",
                    request.getEmail(), makeAdmin, preVerified);

            User user;
            if (makeAdmin) {
                user = preVerified ?
                        createVerifiedAdminUser(request) :
                        userService.createAdminUser(request);
            } else {
                user = preVerified ?
                        userService.createVerifiedUser(request) :
                        userService.createUser(request);
            }

            UserDto userDto = userService.convertUserToDto(user);

            Map<String, Object> response = new HashMap<>();
            response.put("user", userDto);
            response.put("creationInfo", Map.of(
                    "wasAssignedAdminRole", makeAdmin,
                    "wasPreVerified", preVerified,
                    "initialTier", user.getSubscriptionType() + "+" + user.getUserType()
            ));

            return ResponseEntity.status(CREATED)
                    .body(new ApiResponse("User created successfully!", response));
        } catch (AlreadyExistsException e) {
            log.warn("Admin attempt to create user with existing email: {}", request.getEmail());
            return ResponseEntity.status(CONFLICT).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error in admin user creation", e);
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error creating user", null));
        }
    }

    private User createVerifiedAdminUser(CreateUserRequest request) {
        User user = userService.createAdminUser(request);
        user.markEmailAsVerified();
        return user;
    }

    @PostMapping("/admin/create-with-roles")
    @Operation(summary = "Create user with specific roles", description = "Create user with custom role assignment")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> createUserWithRoles(
            @Valid @RequestBody CreateUserRequest request,
            @Parameter(description = "Roles to assign")
            @RequestParam Set<String> roles,
            @Parameter(description = "Create pre-verified")
            @RequestParam(defaultValue = "false") boolean preVerified) {
        try {
            log.info("Admin creating user with email: {} and roles: {}", request.getEmail(), roles);

            User user = userService.createUserWithRoles(request, roles);

            if (preVerified) {
                user.markEmailAsVerified();
            }

            UserDto userDto = userService.convertUserToDto(user);

            return ResponseEntity.status(CREATED)
                    .body(new ApiResponse("User created with custom roles successfully!", userDto));
        } catch (Exception e) {
            log.error("Error creating user with custom roles", e);
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error creating user with roles", null));
        }
    }

    // ===== ENDPOINTS DE UPGRADE (EXISTENTES) =====

    @PostMapping("/{userId}/upgrade-to-pro-seller")
    @Operation(summary = "Upgrade to Pro Seller", description = "Upgrade user to Pro Seller with business information")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> upgradeToProSeller(
            @PathVariable Long userId,
            @Valid @RequestBody UpgradeToProSellerRequest request) {
        try {
            log.info("Upgrading user {} to Pro Seller", userId);

            if (!userService.canUpgradeToProSeller(userId)) {
                return ResponseEntity.status(BAD_REQUEST)
                        .body(new ApiResponse("User cannot be upgraded to Pro Seller", null));
            }

            User user = userService.upgradeToProSeller(userId, request);
            UserDto userDto = userService.convertUserToDto(user);

            return ResponseEntity.ok(new ApiResponse("Successfully upgraded to Pro Seller", userDto));
        } catch (IllegalStateException e) {
            log.warn("Upgrade to Pro Seller failed for user {}: {}", userId, e.getMessage());
            return ResponseEntity.status(CONFLICT).body(new ApiResponse(e.getMessage(), null));
        } catch (ResourceNotFoundException e) {
            log.warn("User not found for Pro Seller upgrade: {}", userId);
            return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error upgrading user {} to Pro Seller", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error upgrading to Pro Seller", null));
        }
    }

    // ===== ENDPOINTS DE INFORMACIÓN MEJORADOS =====

    @GetMapping("/stats")
    @Operation(summary = "Get comprehensive user statistics", description = "Get detailed statistics including roles and tiers")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getDetailedUserStats() {
        try {
            log.info("Retrieving detailed user statistics");

            UserService.UserStats userStats = userService.getUserStats();
            UserService.RoleStats roleStats = userService.getRoleStats();
            UserService.CompleteDistribution distribution = userService.getCompleteDistribution();

            Map<String, Object> response = new HashMap<>();
            response.put("userStats", userStats);
            response.put("roleStats", roleStats);
            response.put("distribution", distribution.configurationDistribution());

            // Análisis y métricas calculadas
            Map<String, Object> analysis = new HashMap<>();
            if (userStats.totalUsers() > 0) {
                analysis.put("verificationRate", (double) userStats.verifiedUsers() / userStats.totalUsers() * 100);
                analysis.put("proConversionRate", (double) userStats.proUsers() / userStats.totalUsers() * 100);
                analysis.put("adminRatio", (double) roleStats.adminUsers() / userStats.totalUsers() * 100);
                analysis.put("proSellerAdminRatio", roleStats.adminUsers() > 0 ?
                        (double) roleStats.adminProSellers() / roleStats.adminUsers() * 100 : 0);
            }
            response.put("analysis", analysis);

            // Salud del sistema
            Map<String, Object> systemHealth = new HashMap<>();
            systemHealth.put("hasAdmins", roleStats.adminUsers() > 0);
            systemHealth.put("adminCount", roleStats.adminUsers());
            systemHealth.put("configurationConsistency",
                    distribution.configurationDistribution().get("FREE+INDIVIDUAL") +
                            distribution.configurationDistribution().get("PRO+PRO_SELLER") == userStats.totalUsers());
            response.put("systemHealth", systemHealth);

            return ResponseEntity.ok(new ApiResponse("Detailed statistics retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving detailed statistics", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving detailed statistics", null));
        }
    }

    @GetMapping("/search")
    @Operation(summary = "Advanced user search", description = "Search users with advanced filtering by roles, tiers, and other criteria")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> searchUsers(
            @Parameter(description = "Search term (name, email, business name)")
            @RequestParam(required = false) String searchTerm,
            @Parameter(description = "Role filter (ROLE_USER, ROLE_ADMIN)")
            @RequestParam(required = false) String role,
            @Parameter(description = "Subscription type filter")
            @RequestParam(required = false) SubscriptionType subscriptionType,
            @Parameter(description = "User type filter")
            @RequestParam(required = false) UserType userType,
            @Parameter(description = "Only verified users")
            @RequestParam(defaultValue = "false") boolean verifiedOnly,
            @Parameter(description = "Only active users")
            @RequestParam(defaultValue = "false") boolean activeOnly,
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            log.info("Advanced search: term={}, role={}, subscription={}, userType={}",
                    searchTerm, role, subscriptionType, userType);

            Pageable pageable = PageRequest.of(page, size, Sort.by("firstName", "lastName"));
            Page<User> usersPage;

            // Lógica de búsqueda inteligente
            if (searchTerm != null && !searchTerm.trim().isEmpty()) {
                usersPage = userService.searchUsers(searchTerm, pageable);
            } else if (role != null && !role.trim().isEmpty()) {
                usersPage = userService.findUsersByRole(role, pageable);
            } else if (subscriptionType != null) {
                usersPage = subscriptionType == SubscriptionType.PRO
                        ? userService.findProUsers(pageable)
                        : userService.findFreeUsers(pageable);
            } else if (userType != null) {
                usersPage = userType == UserType.PRO_SELLER
                        ? userService.findProSellers(pageable)
                        : userService.findIndividualUsers(pageable);
            } else {
                usersPage = activeOnly ?
                        userService.findActiveUsers(pageable) :
                        (verifiedOnly ? userService.findVerifiedUsers(pageable) : userService.findAllUsers(pageable));
            }

            Page<UserDto> userDtoPage = usersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());
            response.put("searchCriteria", Map.of(
                    "searchTerm", searchTerm != null ? searchTerm : "",
                    "role", role != null ? role : "",
                    "subscriptionType", subscriptionType != null ? subscriptionType.toString() : "",
                    "userType", userType != null ? userType.toString() : "",
                    "verifiedOnly", verifiedOnly,
                    "activeOnly", activeOnly
            ));

            return ResponseEntity.ok(new ApiResponse("Advanced search completed successfully", response));
        } catch (Exception e) {
            log.error("Error in advanced search", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error in advanced search", null));
        }
    }

    // ===== ENDPOINTS DE GESTIÓN DE ROLES BÁSICOS =====

    @PostMapping("/{userId}/roles/assign/{roleName}")
    @Operation(summary = "Assign role to user", description = "Assign a specific role to a user (Admin only)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> assignRole(
            @PathVariable Long userId,
            @PathVariable String roleName) {
        try {
            log.info("Assigning role {} to user {}", roleName, userId);

            User user = userService.assignRoleToUser(userId, roleName);
            UserDto userDto = userService.convertUserToDto(user);

            return ResponseEntity.ok(new ApiResponse(
                    String.format("Role %s assigned successfully", roleName), userDto));
        } catch (Exception e) {
            log.error("Error assigning role {} to user {}", roleName, userId, e);
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error assigning role", null));
        }
    }

    @DeleteMapping("/{userId}/roles/remove/{roleName}")
    @Operation(summary = "Remove role from user", description = "Remove a specific role from a user (Admin only)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> removeRole(
            @PathVariable Long userId,
            @PathVariable String roleName) {
        try {
            log.info("Removing role {} from user {}", roleName, userId);

            User user = userService.removeRoleFromUser(userId, roleName);
            UserDto userDto = userService.convertUserToDto(user);

            return ResponseEntity.ok(new ApiResponse(
                    String.format("Role %s removed successfully", roleName), userDto));
        } catch (IllegalStateException e) {
            log.warn("Cannot remove role {} from user {}: {}", roleName, userId, e.getMessage());
            return ResponseEntity.status(CONFLICT)
                    .body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error removing role {} from user {}", roleName, userId, e);
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error removing role", null));
        }
    }

    // ===== ENDPOINTS DE ACTUALIZACIÓN (EXISTENTES MEJORADOS) =====

    @PutMapping("/{userId}")
    @Operation(summary = "Update user", description = "Update user information (preserves roles)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> updateUser(
            @Valid @RequestBody UserUpdateRequest request,
            @PathVariable Long userId) {
        try {
            log.info("Updating user with ID: {}", userId);
            User user = userService.updateUser(request, userId);
            UserDto userDto = userService.convertUserToDto(user);

            Map<String, Object> response = new HashMap<>();
            response.put("user", userDto);
            response.put("preservedRoles", user.getRoles().stream().map(role -> role.getName()).toList());

            return ResponseEntity.ok(new ApiResponse("User updated successfully!", response));
        } catch (ResourceNotFoundException e) {
            log.warn("Attempt to update non-existent user: {}", userId);
            return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error updating user with ID: {}", userId, e);
            return ResponseEntity.status(BAD_REQUEST).body(new ApiResponse("Error updating user", null));
        }
    }

    @PutMapping("/{userId}/contact-info")
    @Operation(summary = "Update contact information", description = "Update user's additional contact information")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> updateContactInfo(
            @PathVariable Long userId,
            @Valid @RequestBody UpdateContactInfoRequest request) {
        try {
            log.info("Updating contact info for user {}", userId);

            User user = userService.updateContactInfo(userId, request);
            UserDto userDto = userService.convertUserToDto(user);

            return ResponseEntity.ok(new ApiResponse("Contact information updated successfully", userDto));
        } catch (Exception e) {
            log.error("Error updating contact info for user {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error updating contact information", null));
        }
    }

    @PutMapping("/{userId}/business-info")
    @Operation(summary = "Update business information", description = "Update business information for Pro Sellers")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> updateBusinessInfo(
            @PathVariable Long userId,
            @Valid @RequestBody UpdateBusinessInfoRequest request) {
        try {
            log.info("Updating business info for user {}", userId);

            User user = userService.updateBusinessInfo(userId, request);
            UserDto userDto = userService.convertUserToDto(user);

            return ResponseEntity.ok(new ApiResponse("Business information updated successfully", userDto));
        } catch (IllegalStateException e) {
            log.warn("Business info update failed for user {}: {}", userId, e.getMessage());
            return ResponseEntity.status(BAD_REQUEST).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error updating business info for user {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error updating business information", null));
        }
    }

    // ===== ENDPOINTS DE ELIMINACIÓN Y ACTIVACIÓN =====

    @DeleteMapping("/{userId}")
    @Operation(summary = "Delete user", description = "Permanently delete a user (checks admin constraints)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> deleteUser(@PathVariable Long userId) {
        try {
            log.info("Deleting user with ID: {}", userId);

            // Verificación adicional para administradores
            User user = userService.getUserById(userId);
            if (user.isAdmin() && !userService.canRevokeAdminPrivileges(userId)) {
                return ResponseEntity.status(CONFLICT)
                        .body(new ApiResponse("Cannot delete user: is the last administrator in the system", null));
            }

            userService.deleteUser(userId);
            return ResponseEntity.ok(new ApiResponse("User deleted successfully!", null));
        } catch (ResourceNotFoundException e) {
            log.warn("Attempt to delete non-existent user: {}", userId);
            return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(e.getMessage(), null));
        } catch (IllegalStateException e) {
            log.warn("Cannot delete user {}: {}", userId, e.getMessage());
            return ResponseEntity.status(CONFLICT).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error deleting user with ID: {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).body(new ApiResponse("Error deleting user", null));
        }
    }

    @PatchMapping("/{userId}/deactivate")
    @Operation(summary = "Deactivate user", description = "Deactivate a user account (soft delete)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> deactivateUser(@PathVariable Long userId) {
        try {
            log.info("Deactivating user with ID: {}", userId);
            User user = userService.deactivateUser(userId);
            UserDto userDto = userService.convertUserToDto(user);
            return ResponseEntity.ok(new ApiResponse("User deactivated successfully!", userDto));
        } catch (Exception e) {
            log.error("Error deactivating user with ID: {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).body(new ApiResponse("Error deactivating user", null));
        }
    }

    @PatchMapping("/{userId}/activate")
    @Operation(summary = "Activate user", description = "Activate a previously deactivated user account")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> activateUser(@PathVariable Long userId) {
        try {
            log.info("Activating user with ID: {}", userId);
            User user = userService.activateUser(userId);
            UserDto userDto = userService.convertUserToDto(user);
            return ResponseEntity.ok(new ApiResponse("User activated successfully!", userDto));
        } catch (Exception e) {
            log.error("Error activating user with ID: {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).body(new ApiResponse("Error activating user", null));
        }
    }

    // ===== ENDPOINTS DE UTILIDAD =====

    @GetMapping("/check-email")
    @Operation(summary = "Check email availability", description = "Check if an email is already registered")
    public ResponseEntity<ApiResponse> checkEmailAvailability(
            @Parameter(description = "Email to check", required = true)
            @RequestParam @Email(message = "Email should be valid")
            @NotBlank(message = "Email is required") String email) {
        try {
            log.debug("Checking email availability for: {}", email);
            boolean exists = userService.existsByEmail(email);

            Map<String, Object> response = new HashMap<>();
            response.put("email", email);
            response.put("available", !exists);
            response.put("exists", exists);

            String message = exists ? "Email is already registered" : "Email is available";
            return ResponseEntity.ok(new ApiResponse(message, response));
        } catch (Exception e) {
            log.error("Error checking email availability for: {}", email, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error checking email availability", null));
        }
    }

    @GetMapping("/{userId}/subscription-info")
    @Operation(summary = "Get subscription information", description = "Get detailed subscription and role information for a user")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> getSubscriptionInfo(@PathVariable Long userId) {
        try {
            log.debug("Getting subscription info for user {}", userId);

            UserService.UserSubscriptionInfo subscriptionInfo = userService.getSubscriptionInfo(userId);
            User user = userService.getUserById(userId);

            Map<String, Object> response = new HashMap<>();
            response.put("subscriptionInfo", subscriptionInfo);
            response.put("roleInfo", Map.of(
                    "roles", user.getRoles().stream().map(role -> role.getName()).toList(),
                    "isAdmin", user.isAdmin(),
                    "permissions", Map.of(
                            "canAccessAdminPanel", user.isAdmin(),
                            "canManageUsers", user.isAdmin(),
                            "canAccessProFeatures", user.canAccessProFeatures()
                    )
            ));

            return ResponseEntity.ok(new ApiResponse("Subscription information retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error getting subscription info for user {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving subscription information", null));
        }
    }

    @GetMapping("/{userId}/upgrade-eligibility")
    @Operation(summary = "Check upgrade eligibility", description = "Check if user can upgrade to Pro Seller")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> getUpgradeEligibility(@PathVariable Long userId) {
        try {
            log.debug("Checking upgrade eligibility for user {}", userId);

            boolean canUpgradeToProSeller = userService.canUpgradeToProSeller(userId);
            User user = userService.getUserById(userId);

            Map<String, Object> eligibility = new HashMap<>();
            eligibility.put("userId", userId);
            eligibility.put("canUpgradeToProSeller", canUpgradeToProSeller);
            eligibility.put("currentTier", user.getSubscriptionType() + "+" + user.getUserType());
            eligibility.put("isValidConfiguration", user.isValidUserConfiguration());
            eligibility.put("requirements", Map.of(
                    "mustBeFreeIndividual", user.isFreeIndividual(),
                    "mustBeEmailVerified", user.isEmailVerified(),
                    "accountMustBeActive", user.isAccountFullyActive()
            ));

            return ResponseEntity.ok(new ApiResponse("Upgrade eligibility checked successfully", eligibility));
        } catch (Exception e) {
            log.error("Error checking upgrade eligibility for user {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error checking upgrade eligibility", null));
        }
    }

    // ===== ENDPOINTS DE EXPORTACIÓN Y REPORTES =====

    @GetMapping("/export")
    @Operation(summary = "Export users", description = "Export user list with comprehensive filtering options")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> exportUsers(
            @Parameter(description = "Export format (csv, json)")
            @RequestParam(defaultValue = "json") String format,
            @Parameter(description = "Include only active users")
            @RequestParam(defaultValue = "true") boolean activeOnly,
            @Parameter(description = "Filter by subscription type")
            @RequestParam(required = false) SubscriptionType subscriptionType,
            @Parameter(description = "Filter by user type")
            @RequestParam(required = false) UserType userType,
            @Parameter(description = "Filter by role")
            @RequestParam(required = false) String role,
            @Parameter(description = "Include role information")
            @RequestParam(defaultValue = "true") boolean includeRoles) {
        try {
            log.info("Exporting users: format={}, activeOnly={}, role={}", format, activeOnly, role);

            Pageable pageable = PageRequest.of(0, 10000, Sort.by("firstName", "lastName")); // Export limit
            Page<User> usersPage;

            // Aplicar filtros de exportación
            if (role != null && !role.trim().isEmpty()) {
                usersPage = userService.findUsersByRole(role, pageable);
            } else if (subscriptionType != null) {
                usersPage = subscriptionType == SubscriptionType.PRO
                        ? userService.findProUsers(pageable)
                        : userService.findFreeUsers(pageable);
            } else if (userType != null) {
                usersPage = userType == UserType.PRO_SELLER
                        ? userService.findProSellers(pageable)
                        : userService.findIndividualUsers(pageable);
            } else {
                usersPage = activeOnly
                        ? userService.findActiveUsers(pageable)
                        : userService.findAllUsers(pageable);
            }

            var userDtos = usersPage.getContent().stream()
                    .map(userService::convertUserToDto)
                    .toList();

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtos);
            response.put("totalCount", usersPage.getTotalElements());
            response.put("exportFormat", format);
            response.put("exportedAt", java.time.LocalDateTime.now());
            response.put("filters", Map.of(
                    "activeOnly", activeOnly,
                    "subscriptionType", subscriptionType,
                    "userType", userType,
                    "role", role != null ? role : "",
                    "includeRoles", includeRoles
            ));

            // Información adicional de estadísticas en la exportación
            if (includeRoles) {
                UserService.CompleteDistribution distribution = userService.getCompleteDistribution();
                response.put("distributionSummary", distribution);
            }

            return ResponseEntity.ok(new ApiResponse("Users exported successfully", response));
        } catch (Exception e) {
            log.error("Error exporting users in format: {}", format, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error exporting users", null));
        }
    }
}
