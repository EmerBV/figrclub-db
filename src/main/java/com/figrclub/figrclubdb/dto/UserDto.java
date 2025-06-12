package com.figrclub.figrclubdb.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.enums.UserType;
import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

/**
 * DTO para representar un usuario en las respuestas de la API
 * Actualizado con campos de suscripción y negocio
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDto {

    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String fullName;
    private String displayName;

    // ===== CAMPOS DE CONTACTO =====
    private String phone;
    private String country;
    private String city;

    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate birthDate;

    // ===== TIPO DE USUARIO Y SUSCRIPCIÓN =====
    private UserType userType;
    private SubscriptionType subscriptionType;

    // ===== CAMPOS DE NEGOCIO (solo para vendedores profesionales) =====
    private String businessName;
    private String businessDescription;
    private String businessLogoUrl;
    private String fiscalAddress;
    private String taxId;
    private String paymentMethod;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime upgradedToProAt;

    // ===== CAMPOS DE ESTADO DEL USUARIO =====
    private boolean enabled;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private boolean admin;

    // ===== ROLES =====
    private List<String> roles;

    // ===== CAMPOS DE AUDITORÍA =====
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createdAt;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime updatedAt;

    private String createdBy;
    private String updatedBy;

    // ===== CAMPOS DE VERIFICACIÓN DE EMAIL =====
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime emailVerifiedAt;

    // ===== CAMPOS ADICIONALES PARA ESTADÍSTICAS =====
    private Long totalUsers; // Para estadísticas en respuestas de admin

    // ===== MÉTODOS ADICIONALES =====

    /**
     * Verifica si el email está verificado
     */
    @JsonProperty("emailVerified")
    public boolean isEmailVerified() {
        return emailVerifiedAt != null;
    }

    /**
     * Verifica si es usuario PRO
     */
    @JsonProperty("isPro")
    public boolean isPro() {
        return subscriptionType == SubscriptionType.PRO;
    }

    /**
     * Verifica si es vendedor profesional
     */
    @JsonProperty("isProSeller")
    public boolean isProSeller() {
        return userType == UserType.PRO_SELLER;
    }

    /**
     * Obtiene el estado de la cuenta
     */
    @JsonProperty("accountStatus")
    public String getAccountStatus() {
        if (!enabled) {
            return "PENDING_VERIFICATION";
        } else if (!accountNonLocked) {
            return "LOCKED";
        } else if (!accountNonExpired) {
            return "EXPIRED";
        } else if (!credentialsNonExpired) {
            return "CREDENTIALS_EXPIRED";
        } else {
            return "ACTIVE";
        }
    }

    /**
     * Obtiene el estado de la suscripción
     */
    @JsonProperty("subscriptionStatus")
    public String getSubscriptionStatus() {
        if (subscriptionType == SubscriptionType.PRO) {
            return upgradedToProAt != null ? "ACTIVE_PRO" : "PRO";
        }
        return "FREE";
    }

    /**
     * Verifica si tiene información de negocio completa
     */
    @JsonProperty("hasCompleteBusinessInfo")
    public boolean hasCompleteBusinessInfo() {
        return isProSeller() &&
                businessName != null && !businessName.trim().isEmpty() &&
                fiscalAddress != null && !fiscalAddress.trim().isEmpty() &&
                taxId != null && !taxId.trim().isEmpty();
    }

    /**
     * Verifica si puede acceder a funcionalidades PRO
     */
    @JsonProperty("canAccessProFeatures")
    public boolean canAccessProFeatures() {
        return isPro() && "ACTIVE".equals(getAccountStatus());
    }

    /**
     * Obtiene información de perfil de contacto completado
     */
    @JsonProperty("contactInfoComplete")
    public boolean isContactInfoComplete() {
        return phone != null && !phone.trim().isEmpty() &&
                country != null && !country.trim().isEmpty() &&
                city != null && !city.trim().isEmpty();
    }
}
