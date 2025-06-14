package com.figrclub.figrclubdb.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.enums.UserType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

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

    // ===== CAMPOS DE IMÁGENES =====

    /**
     * URL de la imagen de perfil activa
     */
    private String profileImageUrl;

    /**
     * URL de la imagen de portada activa (solo para usuarios PRO)
     */
    private String coverImageUrl;

    /**
     * Indica si el usuario tiene imagen de perfil
     */
    private Boolean hasProfileImage;

    /**
     * Indica si el usuario tiene imagen de portada
     */
    private Boolean hasCoverImage;

    /**
     * Número total de imágenes activas del usuario
     */
    private Long activeImageCount;

    /**
     * Información sobre capacidades de imágenes del usuario
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private ImageCapabilitiesDto imageCapabilities;

// ===== CLASE INTERNA PARA CAPACIDADES DE IMÁGENES =====

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ImageCapabilitiesDto {
        private Boolean canUploadProfileImage;
        private Boolean canUploadCoverImage;
        private Long maxProfileImageSize;
        private Long maxCoverImageSize;
        private String maxProfileImageSizeMB;
        private String maxCoverImageSizeMB;
    }

// ===== MÉTODOS DE CONVENIENCIA =====

    /**
     * Obtiene el tamaño máximo de imagen de perfil en MB
     */
    public String getMaxProfileImageSizeMB() {
        if (imageCapabilities != null && imageCapabilities.getMaxProfileImageSize() != null) {
            return String.format("%.1f MB", imageCapabilities.getMaxProfileImageSize() / (1024.0 * 1024.0));
        }
        return "2.0 MB"; // Valor por defecto
    }

    /**
     * Obtiene el tamaño máximo de imagen de portada en MB
     */
    public String getMaxCoverImageSizeMB() {
        if (imageCapabilities != null && imageCapabilities.getMaxCoverImageSize() != null) {
            return String.format("%.1f MB", imageCapabilities.getMaxCoverImageSize() / (1024.0 * 1024.0));
        }
        return "5.0 MB"; // Valor por defecto
    }

    /**
     * Verifica si el usuario puede tener imagen de portada
     */
    public boolean canHaveCoverImage() {
        return subscriptionType == SubscriptionType.PRO;
    }
}