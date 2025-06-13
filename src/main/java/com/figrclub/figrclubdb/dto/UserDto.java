package com.figrclub.figrclubdb.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.enums.UserType;
import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * DTO para representar un usuario en las respuestas de la API
 * ACTUALIZADO para manejar un solo rol inmutable por usuario
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

    // ===== ROL ÚNICO E INMUTABLE =====

    /**
     * CAMBIO PRINCIPAL: Un solo rol en lugar de una lista
     * El rol no puede ser modificado después de la creación del usuario
     */
    @JsonProperty("role")
    private String role;

    /**
     * ID del rol (útil para operaciones internas)
     */
    @JsonProperty("roleId")
    private Long roleId;

    /**
     * Descripción del rol (opcional)
     */
    @JsonProperty("roleDescription")
    private String roleDescription;

    /**
     * Indica si el rol se puede modificar (siempre false para mantener inmutabilidad)
     */
    @JsonProperty("roleModifiable")
    private final boolean roleModifiable = false;

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
     * Verifica si el usuario está completamente activo
     */
    @JsonProperty("active")
    public boolean isActive() {
        return enabled && isEmailVerified() && accountNonLocked && accountNonExpired;
    }

    /**
     * Verifica si es un vendedor profesional
     */
    @JsonProperty("proSeller")
    public boolean isProSeller() {
        return userType == UserType.PRO_SELLER && subscriptionType == SubscriptionType.PRO;
    }

    /**
     * Verifica si es un usuario individual básico
     */
    @JsonProperty("individualUser")
    public boolean isIndividualUser() {
        return userType == UserType.INDIVIDUAL && subscriptionType == SubscriptionType.FREE;
    }

    /**
     * Obtiene el tipo de usuario como string legible
     */
    @JsonProperty("userTypeDisplay")
    public String getUserTypeDisplay() {
        if (isProSeller()) {
            return "Professional Seller";
        } else if (isIndividualUser()) {
            return "Individual User";
        }
        return userType != null ? userType.toString() : "Unknown";
    }

    /**
     * Obtiene el estado de la suscripción como string legible
     */
    @JsonProperty("subscriptionDisplay")
    public String getSubscriptionDisplay() {
        return subscriptionType != null ? subscriptionType.toString() : "Unknown";
    }

    // ===== MÉTODOS DE COMPATIBILIDAD =====

    /**
     * Método de compatibilidad para código existente que espera una lista de roles
     * @deprecated Use getRole() instead
     */
    @Deprecated
    @JsonProperty("roles")
    public java.util.List<String> getRoles() {
        return role != null ? java.util.List.of(role) : java.util.List.of();
    }

    /**
     * Método de compatibilidad para establecer roles (ignora múltiples roles)
     * Solo toma el primer rol de la lista
     * @deprecated Use setRole() instead
     */
    @Deprecated
    public void setRoles(java.util.List<String> roles) {
        if (roles != null && !roles.isEmpty()) {
            this.role = roles.get(0);
        }
    }

    /**
     * Verifica si el usuario tiene un rol específico
     */
    public boolean hasRole(String roleName) {
        return role != null && role.equals(roleName);
    }

    /**
     * Información sobre por qué el rol no se puede modificar
     */
    @JsonProperty("roleModificationReason")
    public String getRoleModificationReason() {
        return "User roles are immutable and cannot be changed after account creation for security reasons";
    }

    // ===== INFORMACIÓN DE ROL PARA LA API =====

    /**
     * Información completa del rol para respuestas de API
     */
    @JsonProperty("roleInfo")
    public RoleInfo getRoleInfo() {
        return new RoleInfo(role, roleId, roleDescription, roleModifiable, admin);
    }

    /**
     * Clase interna para información detallada del rol
     */
    @Data
    public static class RoleInfo {
        private final String name;
        private final Long id;
        private final String description;
        private final boolean modifiable;
        private final boolean isAdmin;
    }
}