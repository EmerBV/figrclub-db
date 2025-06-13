package com.figrclub.figrclubdb.controller;

import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
import com.figrclub.figrclubdb.dto.UserStatistics;
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
 * Controlador de suscripciones CORREGIDO:
 * - Trabaja con rol único inmutable
 * - Solo permite FREE + INDIVIDUAL → PRO + PRO_SELLER
 * - Los roles se mantienen sin cambios durante upgrades
 */
@RestController
@RequestMapping("${api.prefix}/subscriptions")
@RequiredArgsConstructor
@Tag(name = "Subscription Management", description = "Subscription management with immutable roles")
@Slf4j
public class SubscriptionController {

    private final IUserService userService;

    // ===== ÚNICO ENDPOINT DE UPGRADE CORREGIDO =====

    @PostMapping("/upgrade-to-pro-seller")
    @Operation(
            summary = "Upgrade to Pro Seller",
            description = "ÚNICO upgrade disponible: FREE+INDIVIDUAL → PRO+PRO_SELLER (rol se mantiene)"
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

            // Verificar si el usuario puede ser upgradeado
            if (!userService.canUpgradeToProSeller(currentUser.getId())) {
                return ResponseEntity.status(BAD_REQUEST)
                        .body(new ApiResponse("User is not eligible for Pro Seller upgrade", null));
            }

            // Realizar el upgrade (rol se mantiene inmutable)
            User upgradedUser = userService.upgradeToProSeller(currentUser.getId(), request);
            UserDto userDto = userService.convertUserToDto(upgradedUser);

            // Información del upgrade
            Map<String, Object> response = new HashMap<>();
            response.put("user", userDto);
            response.put("upgradeInfo", Map.of(
                    "previousTier", "FREE + INDIVIDUAL",
                    "newTier", "PRO + PRO_SELLER",
                    "rolePreserved", upgradedUser.getRoleName(), // Rol se mantiene igual
                    "upgradeDate", upgradedUser.getUpgradedToProAt(),
                    "newCapabilities", List.of(
                            "Business profile management",
                            "Professional seller features",
                            "Enhanced marketplace access",
                            "Advanced analytics"
                    )
            ));

            log.info("User {} successfully upgraded to PRO_SELLER. Role preserved: {}",
                    currentUser.getId(), upgradedUser.getRoleName());

            return ResponseEntity.ok(new ApiResponse(
                    "Successfully upgraded to Pro Seller! Your role remains unchanged.",
                    response));

        } catch (IllegalStateException e) {
            log.warn("Invalid upgrade attempt: {}", e.getMessage());
            return ResponseEntity.status(BAD_REQUEST).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error during Pro Seller upgrade", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error processing upgrade", null));
        }
    }

    // ===== ENDPOINTS DE INFORMACIÓN Y ESTADÍSTICAS =====

    @GetMapping("/tiers")
    @Operation(summary = "Get subscription tiers", description = "Get available subscription tiers and user distribution")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getSubscriptionTiers() {
        try {
            // CORREGIDO: Cast directo a UserService para acceder al método específico
            UserService userServiceImpl = (UserService) userService;
            UserStatistics stats = userServiceImpl.getUserStatistics();

            Map<String, Object> response = new HashMap<>();
            response.put("availableTiers", Map.of(
                    "FREE_INDIVIDUAL", Map.of(
                            "subscriptionType", "FREE",
                            "userType", "INDIVIDUAL",
                            "description", "Basic individual user with free features",
                            "currentUsers", stats.individualUsers(),
                            "canUpgradeTo", "PRO_PRO_SELLER"
                    ),
                    "PRO_PRO_SELLER", Map.of(
                            "subscriptionType", "PRO",
                            "userType", "PRO_SELLER",
                            "description", "Professional seller with advanced features",
                            "currentUsers", stats.proSellers(),
                            "canUpgradeTo", "none"
                    )
            ));

            response.put("upgradeMatrix", Map.of(
                    "allowedUpgrades", List.of("FREE+INDIVIDUAL → PRO+PRO_SELLER"),
                    "blockedUpgrades", List.of(
                            "PRO+PRO_SELLER → FREE+INDIVIDUAL (downgrade not allowed)",
                            "Any role changes (roles are immutable)"
                    )
            ));

            response.put("statistics", Map.of(
                    "totalUsers", stats.totalUsers(),
                    "freeUsers", stats.freeUsers(),
                    "proUsers", stats.proUsers(),
                    "individualUsers", stats.individualUsers(),
                    "proSellers", stats.proSellers(),
                    "proSellerConversionRate", stats.getProSellerConversionRate()
            ));

            response.put("roleDistribution", userService.getUserStatsByRole());

            return ResponseEntity.ok(new ApiResponse("Subscription tiers information retrieved", response));

        } catch (Exception e) {
            log.error("Error retrieving subscription tiers", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving subscription information", null));
        }
    }

    @GetMapping("/users/free")
    @Operation(summary = "Get free users", description = "Get all users with FREE subscription")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getFreeUsers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            Pageable pageable = PageRequest.of(page, size, Sort.by("firstName", "lastName"));
            Page<User> freeUsersPage = userService.findFreeUsers(pageable);
            Page<UserDto> userDtoPage = freeUsersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());
            response.put("subscriptionType", "FREE");

            // Información adicional
            response.put("upgradeInfo", Map.of(
                    "eligibleForUpgrade", userDtoPage.getContent().stream()
                            .mapToLong(user -> userService.canUpgradeToProSeller(user.getId()) ? 1 : 0)
                            .sum(),
                    "upgradeTarget", "PRO + PRO_SELLER"
            ));

            return ResponseEntity.ok(new ApiResponse("Free users retrieved successfully", response));

        } catch (Exception e) {
            log.error("Error retrieving free users", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving free users", null));
        }
    }

    @GetMapping("/users/pro")
    @Operation(summary = "Get pro users", description = "Get all users with PRO subscription")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getProUsers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            Pageable pageable = PageRequest.of(page, size, Sort.by("firstName", "lastName"));
            Page<User> proUsersPage = userService.findProUsers(pageable);
            Page<UserDto> userDtoPage = proUsersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());
            response.put("subscriptionType", "PRO");

            return ResponseEntity.ok(new ApiResponse("Pro users retrieved successfully", response));

        } catch (Exception e) {
            log.error("Error retrieving pro users", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving pro users", null));
        }
    }

    @GetMapping("/users/pro-sellers")
    @Operation(summary = "Get professional sellers", description = "Get all professional sellers (PRO + PRO_SELLER)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getProSellers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            Pageable pageable = PageRequest.of(page, size, Sort.by("firstName", "lastName"));
            Page<User> proSellersPage = userService.findProSellers(pageable);
            Page<UserDto> userDtoPage = proSellersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());
            response.put("userType", "PRO_SELLER");

            // Información de roles dentro de los Pro Sellers
            long adminProSellers = userDtoPage.getContent().stream()
                    .mapToLong(user -> "ROLE_ADMIN".equals(user.getRole()) ? 1 : 0)
                    .sum();
            long regularProSellers = userDtoPage.getTotalElements() - adminProSellers;

            response.put("roleDistribution", Map.of(
                    "adminProSellers", adminProSellers,
                    "regularProSellers", regularProSellers
            ));

            return ResponseEntity.ok(new ApiResponse("Professional sellers retrieved successfully", response));

        } catch (Exception e) {
            log.error("Error retrieving professional sellers", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving professional sellers", null));
        }
    }

    // ===== ENDPOINT DE VALIDACIÓN =====

    @GetMapping("/validate-user-configuration")
    @Operation(summary = "Validate user configuration", description = "Check if current user has valid tier configuration")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> validateCurrentUserConfiguration() {
        try {
            User currentUser = userService.getAuthenticatedUser();

            // CORREGIDO: Cast directo a UserService para acceder al método específico
            UserService userServiceImpl = (UserService) userService;
            UserService.UserSubscriptionInfo subscriptionInfo =
                    userServiceImpl.getSubscriptionInfo(currentUser.getId());

            Map<String, Object> response = new HashMap<>();
            response.put("userId", currentUser.getId());
            response.put("currentConfiguration", Map.of(
                    "role", currentUser.getRoleName(),
                    "subscriptionType", currentUser.getSubscriptionType(),
                    "userType", currentUser.getUserType(),
                    "tier", currentUser.getSubscriptionType() + " + " + currentUser.getUserType()
            ));

            response.put("isValidConfiguration", currentUser.isValidUserConfiguration());
            response.put("canUpgradeToProSeller", userService.canUpgradeToProSeller(currentUser.getId()));
            response.put("roleImmutable", true);
            response.put("roleModificationReason", userService.getRoleImmutabilityInfo());

            // Opciones disponibles
            Map<String, Object> options = new HashMap<>();
            if (currentUser.isFreeIndividual()) {
                options.put("availableUpgrade", "PRO + PRO_SELLER");
                options.put("upgradeDescription", "Become a professional seller with advanced features");
            } else {
                options.put("availableUpgrade", "none");
                options.put("reason", "Already at highest tier or invalid configuration");
            }
            options.put("isValidConfiguration", currentUser.isValidUserConfiguration());
            response.put("options", options);

            return ResponseEntity.ok(new ApiResponse("User configuration validated", response));

        } catch (Exception e) {
            log.error("Error validating user configuration", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error validating configuration", null));
        }
    }
}