package com.figrclub.figrclubdb.controller;

import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.enums.UserType;
import com.figrclub.figrclubdb.request.UpdateContactInfoRequest;
import com.figrclub.figrclubdb.request.UpdateBusinessInfoRequest;
import com.figrclub.figrclubdb.request.UpgradeToProSellerRequest;
import com.figrclub.figrclubdb.request.UpgradeSubscriptionRequest;
import com.figrclub.figrclubdb.response.ApiResponse;
import com.figrclub.figrclubdb.service.user.IUserService;
import com.figrclub.figrclubdb.service.user.UserService;
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
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpStatus.*;

/**
 * Controlador dedicado a la gestión de suscripciones y actualizaciones de usuario
 * Separa las funcionalidades específicas de suscripción del UserController principal
 */
@RestController
@RequestMapping("${api.prefix}/subscriptions")
@RequiredArgsConstructor
@Tag(name = "Subscription Management", description = "Operations for managing user subscriptions and upgrades")
@Slf4j
public class SubscriptionController {

    private final IUserService userService;

    // ===== ENDPOINTS PARA UPGRADE DE CUENTA =====

    @PostMapping("/upgrade-to-pro-seller")
    @Operation(summary = "Upgrade current user to Pro Seller",
            description = "Upgrade authenticated user to Pro Seller with business information")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> upgradeCurrentUserToProSeller(
            @Valid @RequestBody UpgradeToProSellerRequest request) {
        try {
            User currentUser = userService.getAuthenticatedUser();
            log.info("Current user {} upgrading to Pro Seller", currentUser.getId());

            if (!userService.canUpgradeToProSeller(currentUser.getId())) {
                return ResponseEntity.status(BAD_REQUEST)
                        .body(new ApiResponse("Cannot upgrade to Pro Seller at this time", null));
            }

            User user = userService.upgradeToProSeller(currentUser.getId(), request);
            UserDto userDto = userService.convertUserToDto(user);

            return ResponseEntity.ok(new ApiResponse("Successfully upgraded to Pro Seller!", userDto));
        } catch (IllegalStateException e) {
            log.warn("Pro Seller upgrade failed: {}", e.getMessage());
            return ResponseEntity.status(CONFLICT).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error upgrading to Pro Seller", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error upgrading to Pro Seller", null));
        }
    }

    @PostMapping("/upgrade-to-pro")
    @Operation(summary = "Upgrade current user subscription to PRO",
            description = "Upgrade authenticated user's subscription to PRO")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> upgradeCurrentUserToPro(
            @Valid @RequestBody UpgradeSubscriptionRequest request) {
        try {
            User currentUser = userService.getAuthenticatedUser();
            log.info("Current user {} upgrading subscription to PRO", currentUser.getId());

            if (!userService.canUpgradeSubscription(currentUser.getId())) {
                return ResponseEntity.status(BAD_REQUEST)
                        .body(new ApiResponse("Cannot upgrade subscription at this time", null));
            }

            User user = userService.upgradeSubscriptionToPro(currentUser.getId(), request);
            UserDto userDto = userService.convertUserToDto(user);

            return ResponseEntity.ok(new ApiResponse("Subscription upgraded to PRO successfully!", userDto));
        } catch (IllegalStateException e) {
            log.warn("PRO subscription upgrade failed: {}", e.getMessage());
            return ResponseEntity.status(CONFLICT).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error upgrading subscription to PRO", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error upgrading subscription", null));
        }
    }

    // ===== ENDPOINTS PARA ACTUALIZACIÓN DE INFORMACIÓN =====

    @PutMapping("/contact-info")
    @Operation(summary = "Update contact information",
            description = "Update authenticated user's additional contact information")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> updateContactInfo(
            @Valid @RequestBody UpdateContactInfoRequest request) {
        try {
            User currentUser = userService.getAuthenticatedUser();
            log.info("Updating contact info for current user {}", currentUser.getId());

            User user = userService.updateContactInfo(currentUser.getId(), request);
            UserDto userDto = userService.convertUserToDto(user);

            return ResponseEntity.ok(new ApiResponse("Contact information updated successfully", userDto));
        } catch (IllegalArgumentException e) {
            log.warn("Invalid contact info: {}", e.getMessage());
            return ResponseEntity.status(BAD_REQUEST).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error updating contact info", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error updating contact information", null));
        }
    }

    @PutMapping("/business-info")
    @Operation(summary = "Update business information",
            description = "Update business information for authenticated Pro Seller")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> updateBusinessInfo(
            @Valid @RequestBody UpdateBusinessInfoRequest request) {
        try {
            User currentUser = userService.getAuthenticatedUser();
            log.info("Updating business info for current user {}", currentUser.getId());

            User user = userService.updateBusinessInfo(currentUser.getId(), request);
            UserDto userDto = userService.convertUserToDto(user);

            return ResponseEntity.ok(new ApiResponse("Business information updated successfully", userDto));
        } catch (IllegalStateException e) {
            log.warn("Business info update failed: {}", e.getMessage());
            return ResponseEntity.status(BAD_REQUEST).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error updating business info", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error updating business information", null));
        }
    }

    // ===== ENDPOINTS DE CONSULTA =====

    @GetMapping("/my-subscription")
    @Operation(summary = "Get current subscription info",
            description = "Get detailed subscription information for authenticated user")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> getMySubscriptionInfo() {
        try {
            User currentUser = userService.getAuthenticatedUser();
            log.debug("Getting subscription info for current user {}", currentUser.getId());

            UserService.UserSubscriptionInfo subscriptionInfo = userService.getSubscriptionInfo(currentUser.getId());

            return ResponseEntity.ok(new ApiResponse("Subscription information retrieved successfully", subscriptionInfo));
        } catch (Exception e) {
            log.error("Error getting subscription info", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving subscription information", null));
        }
    }

    @GetMapping("/upgrade-options")
    @Operation(summary = "Get available upgrade options",
            description = "Get available upgrade options for authenticated user")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> getUpgradeOptions() {
        try {
            User currentUser = userService.getAuthenticatedUser();
            log.debug("Getting upgrade options for current user {}", currentUser.getId());

            boolean canUpgradeToProSeller = userService.canUpgradeToProSeller(currentUser.getId());
            boolean canUpgradeSubscription = userService.canUpgradeSubscription(currentUser.getId());

            Map<String, Object> options = new HashMap<>();
            options.put("canUpgradeToProSeller", canUpgradeToProSeller);
            options.put("canUpgradeSubscription", canUpgradeSubscription);
            options.put("currentSubscription", currentUser.getSubscriptionType());
            options.put("currentUserType", currentUser.getUserType());
            options.put("isEmailVerified", currentUser.isEmailVerified());

            // Información adicional sobre beneficios
            Map<String, Object> benefits = new HashMap<>();
            benefits.put("proSellerBenefits", List.of(
                    "Create and manage your own store",
                    "Sell products with professional tools",
                    "Access to advanced analytics",
                    "Priority customer support",
                    "Custom business branding"
            ));
            benefits.put("proBenefits", List.of(
                    "Enhanced features and functionality",
                    "Increased storage and bandwidth",
                    "Advanced customization options",
                    "Priority support"
            ));

            options.put("benefits", benefits);

            return ResponseEntity.ok(new ApiResponse("Upgrade options retrieved successfully", options));
        } catch (Exception e) {
            log.error("Error getting upgrade options", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving upgrade options", null));
        }
    }

    // ===== ENDPOINTS ADMINISTRATIVOS =====

    @GetMapping("/admin/pro-users")
    @Operation(summary = "Get PRO users (Admin)", description = "Get all users with PRO subscription")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getProUsers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            log.info("Admin retrieving PRO users");

            Pageable pageable = PageRequest.of(page, size, Sort.by("upgradedToProAt").descending());
            Page<User> proUsersPage = userService.findProUsers(pageable);
            Page<UserDto> userDtoPage = proUsersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());

            return ResponseEntity.ok(new ApiResponse("PRO users retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving PRO users", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving PRO users", null));
        }
    }

    @GetMapping("/admin/pro-sellers")
    @Operation(summary = "Get Pro Sellers (Admin)", description = "Get all Pro Seller users")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getProSellers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            log.info("Admin retrieving Pro Sellers");

            Pageable pageable = PageRequest.of(page, size, Sort.by("upgradedToProAt").descending());
            Page<User> proSellersPage = userService.findProSellers(pageable);
            Page<UserDto> userDtoPage = proSellersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());

            return ResponseEntity.ok(new ApiResponse("Pro Sellers retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving Pro Sellers", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving Pro Sellers", null));
        }
    }

    @GetMapping("/admin/subscription-stats")
    @Operation(summary = "Get subscription statistics (Admin)",
            description = "Get detailed subscription and conversion statistics")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getSubscriptionStats() {
        try {
            log.info("Admin retrieving subscription statistics");

            var stats = userService.getUserStats();

            Map<String, Object> response = new HashMap<>();
            response.put("totalUsers", stats.totalUsers());
            response.put("freeUsers", stats.freeUsers());
            response.put("proUsers", stats.proUsers());
            response.put("individualUsers", stats.individualUsers());
            response.put("proSellers", stats.proSellers());

            // Calcular estadísticas adicionales
            response.put("proConversionRate", stats.totalUsers() > 0 ?
                    (double) stats.proUsers() / stats.totalUsers() * 100 : 0.0);
            response.put("proSellerConversionRate", stats.totalUsers() > 0 ?
                    (double) stats.proSellers() / stats.totalUsers() * 100 : 0.0);
            response.put("proToProSellerRate", stats.proUsers() > 0 ?
                    (double) stats.proSellers() / stats.proUsers() * 100 : 0.0);

            return ResponseEntity.ok(new ApiResponse("Subscription statistics retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving subscription statistics", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving subscription statistics", null));
        }
    }

    // ===== ENDPOINT PARA POPUP DEL FRONTEND =====

    @GetMapping("/account-type-options")
    @Operation(summary = "Get account type selection options",
            description = "Get options for the post-verification account type selection popup")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> getAccountTypeOptions() {
        try {
            User currentUser = userService.getAuthenticatedUser();
            log.debug("Getting account type options for user {}", currentUser.getId());

            // Verificar que el usuario esté verificado
            if (!currentUser.isEmailVerified()) {
                return ResponseEntity.status(BAD_REQUEST)
                        .body(new ApiResponse("Email must be verified to access account type options", null));
            }

            Map<String, Object> options = new HashMap<>();

            // Información del usuario actual
            options.put("currentUserType", currentUser.getUserType());
            options.put("currentSubscription", currentUser.getSubscriptionType());
            options.put("canUpgrade", userService.canUpgradeToProSeller(currentUser.getId()));

            // Opciones disponibles
            Map<String, Object> individualOption = new HashMap<>();
            individualOption.put("type", UserType.INDIVIDUAL);
            individualOption.put("subscription", SubscriptionType.FREE);
            individualOption.put("title", "Cuenta Personal");
            individualOption.put("description", "Para uso personal y compras ocasionales");
            individualOption.put("features", List.of(
                    "Comprar productos",
                    "Guardar favoritos",
                    "Historial de compras",
                    "Soporte básico"
            ));
            individualOption.put("price", "Gratis");

            Map<String, Object> proSellerOption = new HashMap<>();
            proSellerOption.put("type", UserType.PRO_SELLER);
            proSellerOption.put("subscription", SubscriptionType.PRO);
            proSellerOption.put("title", "Vendedor Profesional");
            proSellerOption.put("description", "Para vender productos y gestionar un negocio");
            proSellerOption.put("features", List.of(
                    "Crear y gestionar tienda",
                    "Vender productos",
                    "Analytics avanzados",
                    "Soporte prioritario",
                    "Branding personalizado"
            ));
            proSellerOption.put("price", "Plan PRO requerido");
            proSellerOption.put("requiresForm", true);

            options.put("accountTypes", List.of(individualOption, proSellerOption));

            return ResponseEntity.ok(new ApiResponse("Account type options retrieved successfully", options));
        } catch (Exception e) {
            log.error("Error getting account type options", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving account type options", null));
        }
    }
}
