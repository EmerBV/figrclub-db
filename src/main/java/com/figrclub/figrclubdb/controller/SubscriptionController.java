package com.figrclub.figrclubdb.controller;

import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.enums.UserType;
import com.figrclub.figrclubdb.request.UpdateContactInfoRequest;
import com.figrclub.figrclubdb.request.UpdateBusinessInfoRequest;
import com.figrclub.figrclubdb.request.UpgradeToProSellerRequest;
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
 * Controlador de suscripciones CORREGIDO con lógica consistente:
 * - Solo permite FREE + INDIVIDUAL
 * - Solo permite PRO + PRO_SELLER
 * - Elimina opciones de upgrade inconsistentes
 */
@RestController
@RequestMapping("${api.prefix}/subscriptions")
@RequiredArgsConstructor
@Tag(name = "Subscription Management", description = "CORRECTED subscription management with consistent logic")
@Slf4j
public class SubscriptionController {

    private final IUserService userService;

    // ===== ÚNICO ENDPOINT DE UPGRADE CORREGIDO =====

    @PostMapping("/upgrade-to-pro-seller")
    @Operation(
            summary = "Upgrade to Pro Seller",
            description = "ÚNICO upgrade disponible: FREE+INDIVIDUAL → PRO+PRO_SELLER"
    )
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> upgradeCurrentUserToProSeller(
            @Valid @RequestBody UpgradeToProSellerRequest request) {
        try {
            User currentUser = userService.getAuthenticatedUser();
            log.info("User {} attempting upgrade from FREE+INDIVIDUAL to PRO+PRO_SELLER", currentUser.getId());

            // Validar que el usuario sea FREE + INDIVIDUAL
            if (!currentUser.isFreeIndividual()) {
                String currentConfig = currentUser.getSubscriptionType() + "+" + currentUser.getUserType();
                return ResponseEntity.status(BAD_REQUEST)
                        .body(new ApiResponse(
                                String.format("Can only upgrade from FREE+INDIVIDUAL. Current: %s", currentConfig),
                                null));
            }

            if (!userService.canUpgradeToProSeller(currentUser.getId())) {
                return ResponseEntity.status(BAD_REQUEST)
                        .body(new ApiResponse("Cannot upgrade to Pro Seller at this time (email not verified?)", null));
            }

            User user = userService.upgradeToProSeller(currentUser.getId(), request);
            UserDto userDto = userService.convertUserToDto(user);

            return ResponseEntity.ok(new ApiResponse(
                    "Successfully upgraded from FREE+INDIVIDUAL to PRO+PRO_SELLER!",
                    userDto));
        } catch (IllegalStateException e) {
            log.warn("Pro Seller upgrade failed: {}", e.getMessage());
            return ResponseEntity.status(CONFLICT).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error upgrading to Pro Seller", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error upgrading to Pro Seller", null));
        }
    }

    // ===== ENDPOINT ELIMINADO =====
    /**
     * MÉTODO ELIMINADO: upgradeCurrentUserToPro
     * Ya no existe upgrade solo de suscripción
     * Solo existe: FREE+INDIVIDUAL → PRO+PRO_SELLER
     */

    // ===== ENDPOINTS DE ACTUALIZACIÓN DE INFORMACIÓN =====

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
            description = "Update business information for authenticated Pro Seller (PRO+PRO_SELLER only)")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> updateBusinessInfo(
            @Valid @RequestBody UpdateBusinessInfoRequest request) {
        try {
            User currentUser = userService.getAuthenticatedUser();
            log.info("Updating business info for current user {}", currentUser.getId());

            // Validar que sea PRO_SELLER
            if (!currentUser.isProSeller()) {
                String currentConfig = currentUser.getSubscriptionType() + "+" + currentUser.getUserType();
                return ResponseEntity.status(BAD_REQUEST)
                        .body(new ApiResponse(
                                String.format("Only PRO+PRO_SELLER can update business info. Current: %s", currentConfig),
                                null));
            }

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

    // ===== ENDPOINTS DE CONSULTA CORREGIDOS =====

    @GetMapping("/my-subscription")
    @Operation(summary = "Get current subscription info",
            description = "Get detailed subscription information for authenticated user")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> getMySubscriptionInfo() {
        try {
            User currentUser = userService.getAuthenticatedUser();
            log.debug("Getting subscription info for current user {}", currentUser.getId());

            UserService.UserSubscriptionInfo subscriptionInfo = userService.getSubscriptionInfo(currentUser.getId());

            // Agregar información adicional sobre la validez de la configuración
            Map<String, Object> response = new HashMap<>();
            response.put("subscriptionInfo", subscriptionInfo);
            response.put("isValidConfiguration", currentUser.isValidUserConfiguration());
            response.put("currentConfiguration", currentUser.getSubscriptionType() + "+" + currentUser.getUserType());

            return ResponseEntity.ok(new ApiResponse("Subscription information retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error getting subscription info", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving subscription information", null));
        }
    }

    @GetMapping("/upgrade-options")
    @Operation(summary = "Get available upgrade options",
            description = "Get available upgrade options for authenticated user (CORRECTED logic)")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> getUpgradeOptions() {
        try {
            User currentUser = userService.getAuthenticatedUser();
            log.debug("Getting CORRECTED upgrade options for user {}", currentUser.getId());

            boolean canUpgradeToProSeller = userService.canUpgradeToProSeller(currentUser.getId());
            String currentConfig = currentUser.getSubscriptionType() + "+" + currentUser.getUserType();

            Map<String, Object> options = new HashMap<>();
            options.put("canUpgradeToProSeller", canUpgradeToProSeller);
            options.put("currentConfiguration", currentConfig);
            options.put("isValidConfiguration", currentUser.isValidUserConfiguration());
            options.put("isEmailVerified", currentUser.isEmailVerified());

            // CORREGIDO: Solo mostrar la opción válida
            if (currentUser.isFreeIndividual()) {
                options.put("availableUpgrade", "PRO+PRO_SELLER");
                options.put("upgradeDescription", "Become a professional seller with all PRO features");
            } else if (currentUser.isProSeller()) {
                options.put("availableUpgrade", "None");
                options.put("upgradeDescription", "You already have the highest tier (PRO+PRO_SELLER)");
            } else {
                // Configuración inconsistente
                options.put("availableUpgrade", "Contact Support");
                options.put("upgradeDescription", "Invalid account configuration detected. Please contact support.");
                options.put("errorMessage", "Invalid user configuration: " + currentConfig);
            }

            // Información sobre beneficios del PRO_SELLER
            Map<String, Object> benefits = new HashMap<>();
            benefits.put("proSellerBenefits", List.of(
                    "Create and manage your own professional store",
                    "Sell products with advanced tools",
                    "Access to comprehensive analytics",
                    "Priority customer support",
                    "Custom business branding",
                    "Advanced payment processing",
                    "Inventory management tools"
            ));

            options.put("benefits", benefits);

            return ResponseEntity.ok(new ApiResponse("CORRECTED upgrade options retrieved successfully", options));
        } catch (Exception e) {
            log.error("Error getting upgrade options", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving upgrade options", null));
        }
    }

    // ===== ENDPOINTS ADMINISTRATIVOS CORREGIDOS =====

    @GetMapping("/admin/pro-users")
    @Operation(summary = "Get PRO users (Admin)",
            description = "Get all PRO+PRO_SELLER users (corrected logic)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getProUsers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            log.info("Admin retrieving PRO users (PRO+PRO_SELLER)");

            Pageable pageable = PageRequest.of(page, size, Sort.by("upgradedToProAt").descending());
            // CORREGIDO: PRO users son siempre PRO_SELLER
            Page<User> proUsersPage = userService.findProSellers(pageable);
            Page<UserDto> userDtoPage = proUsersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());
            response.put("note", "PRO users are always PRO_SELLER in corrected logic");

            return ResponseEntity.ok(new ApiResponse("PRO users (PRO+PRO_SELLER) retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving PRO users", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving PRO users", null));
        }
    }

    @GetMapping("/admin/free-users")
    @Operation(summary = "Get FREE users (Admin)",
            description = "Get all FREE+INDIVIDUAL users (corrected logic)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getFreeUsers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            log.info("Admin retrieving FREE users (FREE+INDIVIDUAL)");

            Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
            // CORREGIDO: FREE users son siempre INDIVIDUAL
            Page<User> freeUsersPage = userService.findIndividualUsers(pageable);
            Page<UserDto> userDtoPage = freeUsersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());
            response.put("note", "FREE users are always INDIVIDUAL in corrected logic");

            return ResponseEntity.ok(new ApiResponse("FREE users (FREE+INDIVIDUAL) retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving FREE users", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving FREE users", null));
        }
    }

    @GetMapping("/admin/subscription-stats")
    @Operation(summary = "Get subscription statistics (Admin)",
            description = "Get CORRECTED subscription and conversion statistics")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getSubscriptionStats() {
        try {
            log.info("Admin retrieving CORRECTED subscription statistics");

            var stats = userService.getUserStats();

            Map<String, Object> response = new HashMap<>();
            response.put("totalUsers", stats.totalUsers());
            response.put("freeIndividualUsers", stats.freeUsers()); // FREE = INDIVIDUAL
            response.put("proSellerUsers", stats.proUsers()); // PRO = PRO_SELLER

            // CORREGIDO: Estadísticas consistentes
            response.put("freeUsers", stats.freeUsers());
            response.put("proUsers", stats.proUsers());
            response.put("individualUsers", stats.individualUsers()); // = freeUsers
            response.put("proSellers", stats.proSellers()); // = proUsers

            // Calcular tasas de conversión corregidas
            response.put("proSellerConversionRate", stats.totalUsers() > 0 ?
                    (double) stats.proSellers() / stats.totalUsers() * 100 : 0.0);

            // Validación de configuraciones
            response.put("configurationNote", "In corrected logic: FREE=INDIVIDUAL, PRO=PRO_SELLER");
            response.put("validConfigurations", List.of("FREE+INDIVIDUAL", "PRO+PRO_SELLER"));

            return ResponseEntity.ok(new ApiResponse("CORRECTED subscription statistics retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving subscription statistics", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving subscription statistics", null));
        }
    }

    // ===== ENDPOINT CORREGIDO PARA POPUP DEL FRONTEND =====

    @GetMapping("/account-type-options")
    @Operation(summary = "Get account type selection options",
            description = "CORRECTED options for post-verification account type selection")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> getAccountTypeOptions() {
        try {
            User currentUser = userService.getAuthenticatedUser();
            log.debug("Getting CORRECTED account type options for user {}", currentUser.getId());

            // Verificar que el usuario esté verificado
            if (!currentUser.isEmailVerified()) {
                return ResponseEntity.status(BAD_REQUEST)
                        .body(new ApiResponse("Email must be verified to access account type options", null));
            }

            Map<String, Object> options = new HashMap<>();

            // Información del usuario actual
            String currentConfig = currentUser.getSubscriptionType() + "+" + currentUser.getUserType();
            options.put("currentConfiguration", currentConfig);
            options.put("isValidConfiguration", currentUser.isValidUserConfiguration());
            options.put("canUpgrade", userService.canUpgradeToProSeller(currentUser.getId()));

            // CORREGIDO: Solo opciones válidas
            Map<String, Object> freeIndividualOption = new HashMap<>();
            freeIndividualOption.put("configuration", "FREE+INDIVIDUAL");
            freeIndividualOption.put("title", "Cuenta Personal Gratuita");
            freeIndividualOption.put("description", "Para uso personal y compras ocasionales");
            freeIndividualOption.put("features", List.of(
                    "Comprar productos",
                    "Guardar favoritos",
                    "Historial de compras",
                    "Soporte básico"
            ));
            freeIndividualOption.put("price", "Gratis");
            freeIndividualOption.put("isCurrent", currentUser.isFreeIndividual());

            Map<String, Object> proSellerOption = new HashMap<>();
            proSellerOption.put("configuration", "PRO+PRO_SELLER");
            proSellerOption.put("title", "Vendedor Profesional");
            proSellerOption.put("description", "Para vender productos y gestionar un negocio profesional");
            proSellerOption.put("features", List.of(
                    "Crear y gestionar tienda profesional",
                    "Vender productos con herramientas avanzadas",
                    "Analytics y reportes completos",
                    "Soporte prioritario",
                    "Branding personalizado",
                    "Procesamiento de pagos avanzado"
            ));
            proSellerOption.put("price", "Suscripción PRO incluida");
            proSellerOption.put("requiresBusinessForm", true);
            proSellerOption.put("isCurrent", currentUser.isProSeller());

            options.put("availableOptions", List.of(freeIndividualOption, proSellerOption));
            options.put("note", "CORRECTED: Only valid combinations shown (FREE+INDIVIDUAL, PRO+PRO_SELLER)");

            return ResponseEntity.ok(new ApiResponse("CORRECTED account type options retrieved successfully", options));
        } catch (Exception e) {
            log.error("Error getting account type options", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving account type options", null));
        }
    }
}
