package com.figrclub.figrclubdb.controller;

import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.enums.UserType;
import com.figrclub.figrclubdb.exceptions.ResourceNotFoundException;
import com.figrclub.figrclubdb.exceptions.RoleModificationException;
import com.figrclub.figrclubdb.response.ApiResponse;
import com.figrclub.figrclubdb.request.UpdateContactInfoRequest;
import com.figrclub.figrclubdb.request.UpdateBusinessInfoRequest;
import com.figrclub.figrclubdb.request.UpgradeToProSellerRequest;
import com.figrclub.figrclubdb.request.UserUpdateRequest;
import com.figrclub.figrclubdb.service.user.IUserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
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

import static org.springframework.http.HttpStatus.*;

/**
 * Controlador de usuarios ACTUALIZADO:
 * - Se eliminan todos los endpoints de modificación de roles
 * - Los roles son inmutables y solo se asignan durante la creación
 * - Se mantiene toda la funcionalidad de gestión de usuarios
 * - Se añaden endpoints informativos sobre la inmutabilidad de roles
 */
@RestController
@RequestMapping("${api.prefix}/users")
@RequiredArgsConstructor
@Tag(name = "User Management", description = "User management operations with immutable roles")
@Validated
@Slf4j
public class UserController {

    private final IUserService userService;

    // ===== ENDPOINTS DE CONSULTA DE USUARIOS =====

    @GetMapping("/{userId}")
    @Operation(summary = "Get user by ID", description = "Retrieve a specific user by their ID")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> getUserById(@PathVariable Long userId) {
        try {
            log.info("Fetching user with ID: {}", userId);
            User user = userService.getUserById(userId);
            UserDto userDto = userService.convertUserToDto(user);

            Map<String, Object> response = new HashMap<>();
            response.put("user", userDto);
            response.put("roleInfo", Map.of(
                    "roleName", user.getRoleName(),
                    "isAdmin", user.isAdmin(),
                    "roleModifiable", false,
                    "roleModificationReason", userService.getRoleImmutabilityInfo()
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
    @Operation(summary = "Get all users", description = "Retrieve all users with advanced filtering")
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

            // LÓGICA DE FILTRADO CON ROLES INMUTABLES
            if (role != null && !role.trim().isEmpty()) {
                usersPage = userService.findUsersByRole(role, pageable);
            } else if (subscriptionType != null && userType != null) {
                usersPage = activeOnly
                        ? userService.findActiveUsers(pageable)
                        : userService.findAllUsers(pageable);
            } else if (subscriptionType != null) {
                usersPage = userService.findProUsers(pageable);
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
            response.put("hasNext", userDtoPage.hasNext());
            response.put("hasPrevious", userDtoPage.hasPrevious());

            // Información sobre roles inmutables
            response.put("roleSystem", Map.of(
                    "rolesAreImmutable", true,
                    "explanation", userService.getRoleImmutabilityInfo(),
                    "availableRoles", userService.getAvailableRoles()
            ));

            return ResponseEntity.ok(new ApiResponse("Users retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving users", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving users", null));
        }
    }

    @GetMapping("/search")
    @Operation(summary = "Search users", description = "Search users by various criteria")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> searchUsers(
            @Parameter(description = "Search term (name, email)")
            @RequestParam(required = false, defaultValue = "") String searchTerm,
            @Parameter(description = "Filter by role")
            @RequestParam(required = false) String role,
            @Parameter(description = "Filter by subscription type")
            @RequestParam(required = false) SubscriptionType subscriptionType,
            @Parameter(description = "Filter by user type")
            @RequestParam(required = false) UserType userType,
            @Parameter(description = "Show only verified users")
            @RequestParam(defaultValue = "false") boolean verifiedOnly,
            @Parameter(description = "Show only active users")
            @RequestParam(defaultValue = "false") boolean activeOnly,
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {

        try {
            log.info("Advanced search with term: '{}', role: {}, subscription: {}, userType: {}",
                    searchTerm, role, subscriptionType, userType);

            Pageable pageable = PageRequest.of(page, size, Sort.by("firstName", "lastName"));
            Page<User> usersPage;

            // Búsqueda con filtros múltiples
            if (searchTerm != null && !searchTerm.trim().isEmpty()) {
                usersPage = userService.searchUsers(searchTerm.trim(), pageable);
            } else if (role != null && !role.trim().isEmpty()) {
                usersPage = userService.findUsersByRole(role, pageable);
            } else if (verifiedOnly) {
                usersPage = userService.findVerifiedUsers(pageable);
            } else if (activeOnly) {
                usersPage = userService.findActiveUsers(pageable);
            } else {
                usersPage = userService.findAllUsers(pageable);
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

    // ===== ENDPOINTS INFORMATIVOS SOBRE ROLES =====

    @GetMapping("/{userId}/role")
    @Operation(summary = "Get user role", description = "Get the immutable role of a specific user")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> getUserRole(@PathVariable Long userId) {
        try {
            log.info("Getting role for user: {}", userId);

            String roleName = userService.getUserRoleName(userId);
            boolean isAdmin = userService.userHasRole(userId, "ROLE_ADMIN");

            Map<String, Object> response = new HashMap<>();
            response.put("userId", userId);
            response.put("roleName", roleName);
            response.put("isAdmin", isAdmin);
            response.put("roleModifiable", false);
            response.put("immutabilityInfo", userService.getRoleImmutabilityInfo());

            return ResponseEntity.ok(new ApiResponse("User role retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error getting role for user: {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving user role", null));
        }
    }

    @GetMapping("/roles/policy")
    @Operation(summary = "Get role policy", description = "Get information about the immutable role policy")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> getRolePolicy() {
        try {
            Map<String, Object> response = new HashMap<>();
            response.put("policy", "IMMUTABLE_ROLES");
            response.put("description", userService.getRoleImmutabilityInfo());
            response.put("availableRoles", userService.getAvailableRoles());
            response.put("roleAssignmentTime", "ACCOUNT_CREATION_ONLY");
            response.put("canModifyRoles", false);
            response.put("reasonForImmutability", "Security and data integrity");

            return ResponseEntity.ok(new ApiResponse("Role policy retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving role policy", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving role policy", null));
        }
    }

    // ===== ENDPOINTS DE ACTUALIZACIÓN (SIN ROLES) =====

    @PutMapping("/{userId}")
    @Operation(summary = "Update user", description = "Update user information (roles are preserved and cannot be modified)")
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
            response.put("preservedRole", user.getRoleName());
            response.put("roleModificationAttempted", false);
            response.put("message", "User updated successfully. Role preserved as immutable.");

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
    @Operation(summary = "Update contact information", description = "Update user's contact information")
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
        } catch (ResourceNotFoundException e) {
            log.warn("User not found for contact update: {}", userId);
            return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error updating contact info for user: {}", userId, e);
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error updating contact information", null));
        }
    }

    @PutMapping("/{userId}/business-info")
    @Operation(summary = "Update business information", description = "Update business information for professional sellers")
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
            log.warn("Invalid business info update attempt for user: {}", userId);
            return ResponseEntity.status(BAD_REQUEST).body(new ApiResponse(e.getMessage(), null));
        } catch (ResourceNotFoundException e) {
            log.warn("User not found for business update: {}", userId);
            return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error updating business info for user: {}", userId, e);
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error updating business information", null));
        }
    }

    // ===== UPGRADE DE USUARIO (SIN CAMBIO DE ROL) =====

    @PostMapping("/{userId}/upgrade-to-pro-seller")
    @Operation(summary = "Upgrade to Pro Seller", description = "Upgrade user to professional seller (role remains unchanged)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> upgradeToProSeller(
            @PathVariable Long userId,
            @Valid @RequestBody UpgradeToProSellerRequest request) {
        try {
            log.info("Upgrading user {} to Pro Seller", userId);

            if (!userService.canUpgradeToProSeller(userId)) {
                return ResponseEntity.status(BAD_REQUEST)
                        .body(new ApiResponse("User is not eligible for Pro Seller upgrade", null));
            }

            User user = userService.upgradeToProSeller(userId, request);
            UserDto userDto = userService.convertUserToDto(user);

            Map<String, Object> response = new HashMap<>();
            response.put("user", userDto);
            response.put("previousTier", "FREE + INDIVIDUAL");
            response.put("newTier", "PRO + PRO_SELLER");
            response.put("rolePreserved", user.getRoleName());
            response.put("upgradeDate", user.getUpgradedToProAt());

            return ResponseEntity.ok(new ApiResponse("User upgraded to Pro Seller successfully", response));
        } catch (IllegalStateException e) {
            log.warn("Invalid upgrade attempt for user: {}", userId);
            return ResponseEntity.status(BAD_REQUEST).body(new ApiResponse(e.getMessage(), null));
        } catch (ResourceNotFoundException e) {
            log.warn("User not found for upgrade: {}", userId);
            return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error upgrading user to Pro Seller: {}", userId, e);
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error upgrading to Pro Seller", null));
        }
    }

    // ===== ENDPOINTS BLOQUEADOS (MODIFICACIÓN DE ROLES) =====

    /**
     * Endpoint bloqueado: Asignación de roles
     * Responde con información sobre por qué no está disponible
     */
    @PostMapping("/{userId}/roles/assign/{roleName}")
    @Operation(summary = "Assign role (BLOCKED)", description = "This endpoint is blocked because roles are immutable")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> assignRole(
            @PathVariable Long userId,
            @PathVariable String roleName) {

        log.warn("Blocked attempt to assign role {} to user {}", roleName, userId);

        Map<String, Object> response = new HashMap<>();
        response.put("operationBlocked", true);
        response.put("reason", "IMMUTABLE_ROLES");
        response.put("explanation", userService.getRoleImmutabilityInfo());
        response.put("alternative", "Roles can only be assigned during user creation");
        response.put("currentUserRole", userService.getUserRoleName(userId));

        return ResponseEntity.status(FORBIDDEN)
                .body(new ApiResponse("Role modification is not allowed", response));
    }

    /**
     * Endpoint bloqueado: Remoción de roles
     * Responde con información sobre por qué no está disponible
     */
    @DeleteMapping("/{userId}/roles/remove/{roleName}")
    @Operation(summary = "Remove role (BLOCKED)", description = "This endpoint is blocked because roles are immutable")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> removeRole(
            @PathVariable Long userId,
            @PathVariable String roleName) {

        log.warn("Blocked attempt to remove role {} from user {}", roleName, userId);

        Map<String, Object> response = new HashMap<>();
        response.put("operationBlocked", true);
        response.put("reason", "IMMUTABLE_ROLES");
        response.put("explanation", userService.getRoleImmutabilityInfo());
        response.put("alternative", "User accounts must be recreated to change roles");
        response.put("currentUserRole", userService.getUserRoleName(userId));

        return ResponseEntity.status(FORBIDDEN)
                .body(new ApiResponse("Role modification is not allowed", response));
    }

    /**
     * Endpoint bloqueado: Promoción a admin
     * Responde con información sobre por qué no está disponible
     */
    @PostMapping("/{userId}/promote-to-admin")
    @Operation(summary = "Promote to admin (BLOCKED)", description = "This endpoint is blocked because roles are immutable")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> promoteToAdmin(@PathVariable Long userId) {

        log.warn("Blocked attempt to promote user {} to admin", userId);

        Map<String, Object> response = new HashMap<>();
        response.put("operationBlocked", true);
        response.put("reason", "IMMUTABLE_ROLES");
        response.put("explanation", userService.getRoleImmutabilityInfo());
        response.put("alternative", "Create a new admin account instead");
        response.put("currentUserRole", userService.getUserRoleName(userId));

        return ResponseEntity.status(FORBIDDEN)
                .body(new ApiResponse("Role promotion is not allowed", response));
    }

    /**
     * Endpoint bloqueado: Revocación de admin
     * Responde con información sobre por qué no está disponible
     */
    @PostMapping("/{userId}/revoke-admin")
    @Operation(summary = "Revoke admin (BLOCKED)", description = "This endpoint is blocked because roles are immutable")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> revokeAdmin(@PathVariable Long userId) {

        log.warn("Blocked attempt to revoke admin from user {}", userId);

        Map<String, Object> response = new HashMap<>();
        response.put("operationBlocked", true);
        response.put("reason", "IMMUTABLE_ROLES");
        response.put("explanation", userService.getRoleImmutabilityInfo());
        response.put("alternative", "Disable the admin account instead");
        response.put("currentUserRole", userService.getUserRoleName(userId));

        return ResponseEntity.status(FORBIDDEN)
                .body(new ApiResponse("Role revocation is not allowed", response));
    }

    // ===== ENDPOINT DE ELIMINACIÓN =====

    @DeleteMapping("/{userId}")
    @Operation(summary = "Delete user", description = "Delete a user (Admin only)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> deleteUser(@PathVariable Long userId) {
        try {
            log.info("Deleting user with ID: {}", userId);

            // Verificar que no sea el último admin
            String userRole = userService.getUserRoleName(userId);
            if ("ROLE_ADMIN".equals(userRole)) {
                long adminCount = userService.countAdminUsers();
                if (adminCount <= 1) {
                    return ResponseEntity.status(BAD_REQUEST)
                            .body(new ApiResponse("Cannot delete the last admin user", null));
                }
            }

            userService.deleteUser(userId);

            Map<String, Object> response = new HashMap<>();
            response.put("deletedUserId", userId);
            response.put("deletedUserRole", userRole);
            response.put("message", "User deleted successfully");

            return ResponseEntity.ok(new ApiResponse("User deleted successfully", response));
        } catch (ResourceNotFoundException e) {
            log.warn("Attempt to delete non-existent user: {}", userId);
            return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error deleting user with ID: {}", userId, e);
            return ResponseEntity.status(BAD_REQUEST).body(new ApiResponse("Error deleting user", null));
        }
    }

    // ===== ENDPOINTS DE ESTADÍSTICAS =====

    @GetMapping("/stats")
    @Operation(summary = "Get user statistics", description = "Get comprehensive user statistics")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getUserStats() {
        try {
            log.info("Retrieving user statistics");

            Map<String, Object> response = new HashMap<>();

            // Estadísticas por rol
            response.put("roleStats", userService.getUserStatsByRole());

            // Estadísticas por tipo y suscripción
            response.put("tierStats", userService.getUserStatsByTypeAndSubscription());

            // Contadores generales
            response.put("generalStats", Map.of(
                    "totalUsers", userService.findAllUsers(Pageable.unpaged()).getTotalElements(),
                    "activeUsers", userService.countActiveUsers(),
                    "verifiedUsers", userService.countVerifiedUsers(),
                    "adminUsers", userService.countAdminUsers(),
                    "regularUsers", userService.countRegularUsers()
            ));

            // Información del sistema de roles
            response.put("roleSystem", Map.of(
                    "rolesAreImmutable", true,
                    "availableRoles", userService.getAvailableRoles(),
                    "policy", userService.getRoleImmutabilityInfo()
            ));

            return ResponseEntity.ok(new ApiResponse("User statistics retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving user statistics", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving user statistics", null));
        }
    }

    // ===== MANEJO DE EXCEPCIONES ESPECÍFICAS =====

    /**
     * Maneja intentos de modificación de roles que lleguen al servicio
     */
    @ExceptionHandler(RoleModificationException.class)
    public ResponseEntity<ApiResponse> handleRoleModificationException(RoleModificationException e) {
        log.warn("Role modification attempt blocked: {}", e.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("error", "ROLE_MODIFICATION_BLOCKED");
        response.put("reason", e.getMessage());
        response.put("policy", userService.getRoleImmutabilityInfo());
        response.put("availableRoles", userService.getAvailableRoles());

        return ResponseEntity.status(FORBIDDEN)
                .body(new ApiResponse("Role modification is not allowed", response));
    }

}
