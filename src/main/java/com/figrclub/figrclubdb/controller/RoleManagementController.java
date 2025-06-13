package com.figrclub.figrclubdb.controller;

import com.figrclub.figrclubdb.response.ApiResponse;
import com.figrclub.figrclubdb.service.user.IUserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpStatus.*;

/**
 * Controlador de gestión de roles DESHABILITADO
 *
 * Este controlador ahora sirve únicamente para informar que las operaciones
 * de modificación de roles están deshabilitadas debido a la política de roles inmutables.
 *
 * Todos los endpoints ahora devuelven mensajes informativos explicando:
 * - Por qué los roles son inmutables
 * - Cuáles son las alternativas disponibles
 * - Cómo funciona el nuevo sistema de roles
 */
@RestController
@RequestMapping("${api.prefix}/users/roles")
@RequiredArgsConstructor
@Tag(name = "Role Management (DISABLED)", description = "Role management operations are disabled - roles are immutable")
@Validated
@Slf4j
public class RoleManagementController {

    private final IUserService userService;

    // ===== ENDPOINT INFORMATIVO PRINCIPAL =====

    @GetMapping("/policy")
    @Operation(summary = "Get role management policy", description = "Information about why role management is disabled")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> getRoleManagementPolicy() {
        try {
            Map<String, Object> response = new HashMap<>();
            response.put("policyStatus", "ROLE_MANAGEMENT_DISABLED");
            response.put("reason", "Roles are now immutable for security and data integrity");
            response.put("explanation", userService.getRoleImmutabilityInfo());
            response.put("roleAssignmentTime", "ACCOUNT_CREATION_ONLY");
            response.put("availableRoles", userService.getAvailableRoles());
            response.put("modificationAllowed", false);
            response.put("alternatives", Map.of(
                    "changeRole", "Create a new account with the desired role",
                    "adminAccess", "Create dedicated admin accounts",
                    "userManagement", "Use user account status controls (enable/disable)",
                    "permissions", "Manage permissions through user type and subscription tiers"
            ));

            return ResponseEntity.ok(new ApiResponse("Role management policy retrieved", response));
        } catch (Exception e) {
            log.error("Error retrieving role management policy", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving policy information", null));
        }
    }

    // ===== ENDPOINTS DE CONSULTA (MANTENIDOS PARA COMPATIBILIDAD) =====

    @GetMapping("/{userId}")
    @Operation(summary = "Get user role (Read-only)", description = "Get the immutable role of a specific user")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> getUserRole(@PathVariable Long userId) {
        try {
            log.info("Getting role for user: {} (read-only)", userId);

            String roleName = userService.getUserRoleName(userId);
            boolean isAdmin = userService.userHasRole(userId, "ROLE_ADMIN");

            Map<String, Object> response = new HashMap<>();
            response.put("userId", userId);
            response.put("roleName", roleName);
            response.put("isAdmin", isAdmin);
            response.put("roleModifiable", false);
            response.put("roleManagementDisabled", true);
            response.put("reason", userService.getRoleImmutabilityInfo());

            return ResponseEntity.ok(new ApiResponse("User role retrieved (read-only)", response));
        } catch (Exception e) {
            log.error("Error getting role for user: {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving user role", null));
        }
    }

    // ===== ENDPOINTS BLOQUEADOS CON MENSAJES INFORMATIVOS =====

    @PostMapping("/{userId}/assign/{roleName}")
    @Operation(summary = "Assign role (DISABLED)", description = "Role assignment is disabled - roles are immutable")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> assignRoleToUser(
            @Parameter(description = "User ID")
            @PathVariable Long userId,
            @Parameter(description = "Role name (operation will be blocked)")
            @PathVariable String roleName) {

        log.warn("Blocked role assignment attempt: role {} to user {}", roleName, userId);

        Map<String, Object> response = new HashMap<>();
        response.put("operationBlocked", true);
        response.put("requestedOperation", "ASSIGN_ROLE");
        response.put("requestedRole", roleName);
        response.put("targetUserId", userId);
        response.put("currentUserRole", userService.getUserRoleName(userId));
        response.put("reason", "IMMUTABLE_ROLES_POLICY");
        response.put("explanation", userService.getRoleImmutabilityInfo());
        response.put("alternatives", Map.of(
                "createNewUser", "Create a new user account with the desired role",
                "manageAccess", "Use account status (enable/disable) to control access",
                "tierManagement", "Modify user type and subscription for feature access"
        ));

        return ResponseEntity.status(FORBIDDEN)
                .body(new ApiResponse("Role assignment is disabled", response));
    }

    @DeleteMapping("/{userId}/remove/{roleName}")
    @Operation(summary = "Remove role (DISABLED)", description = "Role removal is disabled - roles are immutable")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> removeRoleFromUser(
            @Parameter(description = "User ID")
            @PathVariable Long userId,
            @Parameter(description = "Role name (operation will be blocked)")
            @PathVariable String roleName) {

        log.warn("Blocked role removal attempt: role {} from user {}", roleName, userId);

        Map<String, Object> response = new HashMap<>();
        response.put("operationBlocked", true);
        response.put("requestedOperation", "REMOVE_ROLE");
        response.put("requestedRole", roleName);
        response.put("targetUserId", userId);
        response.put("currentUserRole", userService.getUserRoleName(userId));
        response.put("reason", "IMMUTABLE_ROLES_POLICY");
        response.put("explanation", userService.getRoleImmutabilityInfo());
        response.put("alternatives", Map.of(
                "disableAccount", "Disable the user account instead of changing roles",
                "deleteAccount", "Delete the account if role change is absolutely necessary",
                "createNewAccount", "Create a new account with the correct role"
        ));

        return ResponseEntity.status(FORBIDDEN)
                .body(new ApiResponse("Role removal is disabled", response));
    }

    @PostMapping("/{userId}/promote-to-admin")
    @Operation(summary = "Promote to admin (DISABLED)", description = "Admin promotion is disabled - roles are immutable")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> promoteToAdmin(@PathVariable Long userId) {

        log.warn("Blocked admin promotion attempt for user: {}", userId);

        Map<String, Object> response = new HashMap<>();
        response.put("operationBlocked", true);
        response.put("requestedOperation", "PROMOTE_TO_ADMIN");
        response.put("targetUserId", userId);
        response.put("currentUserRole", userService.getUserRoleName(userId));
        response.put("reason", "IMMUTABLE_ROLES_POLICY");
        response.put("explanation", userService.getRoleImmutabilityInfo());
        response.put("alternatives", Map.of(
                "createAdminAccount", "Create a new user account with ROLE_ADMIN",
                "useExistingAdmin", "Use existing admin accounts for administrative tasks"
        ));

        return ResponseEntity.status(FORBIDDEN)
                .body(new ApiResponse("Admin promotion is disabled", response));
    }

    @PostMapping("/{userId}/revoke-admin")
    @Operation(summary = "Revoke admin (DISABLED)", description = "Admin revocation is disabled - roles are immutable")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> revokeAdminPrivileges(@PathVariable Long userId) {

        log.warn("Blocked admin revocation attempt for user: {}", userId);

        Map<String, Object> response = new HashMap<>();
        response.put("operationBlocked", true);
        response.put("requestedOperation", "REVOKE_ADMIN");
        response.put("targetUserId", userId);
        response.put("currentUserRole", userService.getUserRoleName(userId));
        response.put("reason", "IMMUTABLE_ROLES_POLICY");
        response.put("explanation", userService.getRoleImmutabilityInfo());
        response.put("alternatives", Map.of(
                "disableAccount", "Disable the admin account to prevent access",
                "deleteAccount", "Delete the admin account if no longer needed"
        ));

        return ResponseEntity.status(FORBIDDEN)
                .body(new ApiResponse("Admin revocation is disabled", response));
    }

    @PutMapping("/{userId}/update-roles")
    @Operation(summary = "Update roles (DISABLED)", description = "Role updates are disabled - roles are immutable")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> updateUserRoles(
            @PathVariable Long userId,
            @RequestBody Map<String, Object> roleUpdateRequest) {

        log.warn("Blocked role update attempt for user: {}", userId);

        Map<String, Object> response = new HashMap<>();
        response.put("operationBlocked", true);
        response.put("requestedOperation", "UPDATE_ROLES");
        response.put("targetUserId", userId);
        response.put("requestedChanges", roleUpdateRequest);
        response.put("currentUserRole", userService.getUserRoleName(userId));
        response.put("reason", "IMMUTABLE_ROLES_POLICY");
        response.put("explanation", userService.getRoleImmutabilityInfo());
        response.put("alternatives", Map.of(
                "recreateAccount", "Delete and recreate the account with correct role",
                "manageOtherAttributes", "Modify user type, subscription, or account status instead"
        ));

        return ResponseEntity.status(FORBIDDEN)
                .body(new ApiResponse("Role updates are disabled", response));
    }

    // ===== ENDPOINTS INFORMATIVOS SOBRE EL SISTEMA =====

    @GetMapping("/available-roles")
    @Operation(summary = "Get available roles", description = "List all available roles in the system")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getAvailableRoles() {
        try {
            Map<String, Object> response = new HashMap<>();
            response.put("availableRoles", userService.getAvailableRoles());
            response.put("roleAssignmentPolicy", "CREATION_TIME_ONLY");
            response.put("modificationAllowed", false);
            response.put("explanation", userService.getRoleImmutabilityInfo());

            return ResponseEntity.ok(new ApiResponse("Available roles retrieved", response));
        } catch (Exception e) {
            log.error("Error retrieving available roles", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving available roles", null));
        }
    }

    @GetMapping("/system-info")
    @Operation(summary = "Get role system information", description = "Get comprehensive information about the role system")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getRoleSystemInfo() {
        try {
            Map<String, Object> response = new HashMap<>();
            response.put("systemType", "IMMUTABLE_ROLES");
            response.put("version", "2.0");
            response.put("policy", userService.getRoleImmutabilityInfo());
            response.put("features", Map.of(
                    "roleModification", false,
                    "roleAssignmentAtCreation", true,
                    "roleQuerying", true,
                    "userTypeModification", true,
                    "subscriptionModification", true
            ));
            response.put("statistics", userService.getUserStatsByRole());
            response.put("migrationDate", "2024-CURRENT");
            response.put("documentation", "Roles are now immutable to ensure data integrity and security");

            return ResponseEntity.ok(new ApiResponse("Role system information retrieved", response));
        } catch (Exception e) {
            log.error("Error retrieving role system information", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving system information", null));
        }
    }
}