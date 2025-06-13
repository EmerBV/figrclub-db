package com.figrclub.figrclubdb.domain.model;

import com.figrclub.figrclubdb.domain.base.Auditable;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.enums.UserType;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.hibernate.annotations.NaturalId;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * Entidad User MODIFICADA para tener un solo rol inmutable:
 * - Un usuario tiene exactamente UN rol que se asigna al crear la cuenta
 * - El rol NO se puede modificar después de la creación
 * - FREE + INDIVIDUAL = Usuario básico gratuito
 * - PRO + PRO_SELLER = Vendedor profesional con suscripción PRO
 */
@Getter
@Setter
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "users", indexes = {
        @Index(name = "idx_user_email", columnList = "email"),
        @Index(name = "idx_user_enabled", columnList = "is_enabled"),
        @Index(name = "idx_user_email_verified", columnList = "email_verified_at"),
        @Index(name = "idx_user_subscription", columnList = "subscription_type"),
        @Index(name = "idx_user_type", columnList = "user_type"),
        @Index(name = "idx_user_role", columnList = "role_id") // Nuevo índice para el rol único
})
public class User extends Auditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // ===== CAMPOS BÁSICOS DE REGISTRO =====
    @NotBlank(message = "First name is required")
    @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
    @Column(name = "first_name", nullable = false, length = 50)
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
    @Column(name = "last_name", nullable = false, length = 50)
    private String lastName;

    @NaturalId
    @Email(message = "Please provide a valid email")
    @NotBlank(message = "Email is required")
    @Column(nullable = false, unique = true, length = 100)
    private String email;

    @NotBlank(message = "Password is required")
    @Column(nullable = false)
    private String password;

    // ===== CAMPOS DE CONTACTO ADICIONALES =====
    @Column(name = "phone", length = 20)
    private String phone;

    @Column(name = "country", length = 100)
    private String country;

    @Column(name = "city", length = 100)
    private String city;

    @Column(name = "birth_date")
    private LocalDate birthDate;

    // ===== TIPO DE USUARIO Y SUSCRIPCIÓN (LÓGICA CONSISTENTE) =====
    @Enumerated(EnumType.STRING)
    @Column(name = "user_type", nullable = false)
    @Builder.Default
    private UserType userType = UserType.INDIVIDUAL;

    @Enumerated(EnumType.STRING)
    @Column(name = "subscription_type", nullable = false)
    @Builder.Default
    private SubscriptionType subscriptionType = SubscriptionType.FREE;

    // ===== CAMPOS PARA VENDEDORES PROFESIONALES =====
    @Column(name = "business_name", length = 200)
    private String businessName;

    @Column(name = "business_description", columnDefinition = "TEXT")
    private String businessDescription;

    @Column(name = "business_logo_url", length = 500)
    private String businessLogoUrl;

    @Column(name = "fiscal_address", columnDefinition = "TEXT")
    private String fiscalAddress;

    @Column(name = "tax_id", length = 50)
    private String taxId;

    @Column(name = "payment_method", length = 100)
    private String paymentMethod;

    @Column(name = "upgraded_to_pro_at")
    private LocalDateTime upgradedToProAt;

    // ===== CAMPOS DE ESTADO DE CUENTA =====
    @Builder.Default
    @Column(name = "is_enabled", nullable = false)
    private boolean isEnabled = false;

    @Column(name = "email_verified_at")
    private LocalDateTime emailVerifiedAt;

    @Builder.Default
    @Column(name = "is_account_non_expired", nullable = false)
    private boolean isAccountNonExpired = true;

    @Builder.Default
    @Column(name = "is_account_non_locked", nullable = false)
    private boolean isAccountNonLocked = true;

    @Builder.Default
    @Column(name = "is_credentials_non_expired", nullable = false)
    private boolean isCredentialsNonExpired = true;

    // ===== ROL ÚNICO E INMUTABLE =====
    /**
     * CAMBIO PRINCIPAL: Un usuario tiene exactamente un rol que NO se puede modificar
     * El rol se asigna durante la creación del usuario y permanece fijo
     */
    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "role_id", nullable = false, updatable = false) // updatable = false impide modificaciones
    private Role role;

    // ===== MÉTODOS DE UTILIDAD =====

    /**
     * Obtiene el nombre completo del usuario
     */
    public String getFullName() {
        return firstName + " " + lastName;
    }

    /**
     * Obtiene el nombre para mostrar (nombre completo)
     */
    public String getDisplayName() {
        return getFullName();
    }

    /**
     * Verifica si el usuario es administrador
     */
    public boolean isAdmin() {
        return role != null && "ROLE_ADMIN".equals(role.getName());
    }

    /**
     * Verifica si el usuario tiene un rol específico
     * @param roleName Nombre del rol a verificar
     * @return true si el usuario tiene ese rol
     */
    public boolean hasRole(String roleName) {
        return role != null && role.getName().equals(roleName);
    }

    /**
     * Obtiene el nombre del rol del usuario
     * @return Nombre del rol o null si no tiene rol asignado
     */
    public String getRoleName() {
        return role != null ? role.getName() : null;
    }

    /**
     * Verifica si el usuario es un vendedor profesional
     */
    public boolean isProSeller() {
        return userType == UserType.PRO_SELLER && subscriptionType == SubscriptionType.PRO;
    }

    /**
     * Verifica si el usuario es un usuario individual básico
     */
    public boolean isIndividualUser() {
        return userType == UserType.INDIVIDUAL && subscriptionType == SubscriptionType.FREE;
    }

    /**
     * Verifica si el email está verificado
     */
    public boolean isEmailVerified() {
        return emailVerifiedAt != null;
    }

    /**
     * Verifica si el usuario está completamente activo
     */
    public boolean isActive() {
        return isEnabled && isEmailVerified() && isAccountNonLocked && isAccountNonExpired;
    }

    /**
     * Marca el email como verificado
     */
    public void markEmailAsVerified() {
        this.emailVerifiedAt = LocalDateTime.now();
        this.isEnabled = true; // Activar automáticamente al verificar email
    }

    /**
     * Verifica si es una configuración de usuario válida
     */
    public boolean isValidUserConfiguration() {
        // Validar combinaciones coherentes de tipo y suscripción
        if (userType == UserType.PRO_SELLER && subscriptionType != SubscriptionType.PRO) {
            return false;
        }
        if (userType == UserType.INDIVIDUAL && subscriptionType == SubscriptionType.PRO) {
            return false;
        }
        // Validar que tiene rol asignado
        return role != null;
    }

    /**
     * Verifica si es un usuario individual gratuito
     */
    public boolean isFreeIndividual() {
        return userType == UserType.INDIVIDUAL && subscriptionType == SubscriptionType.FREE;
    }

    /**
     * Actualiza información de negocio (solo para vendedores profesionales)
     */
    public void updateBusinessInfo(String businessName, String businessDescription, String businessLogoUrl) {
        if (!isProSeller()) {
            throw new IllegalStateException("Only professional sellers can update business information");
        }
        this.businessName = businessName;
        this.businessDescription = businessDescription;
        this.businessLogoUrl = businessLogoUrl;
    }

    /**
     * Verifica si puede acceder a funciones profesionales
     */
    public boolean canAccessProFeatures() {
        return isProSeller();
    }

    /**
     * Verifica si la cuenta está completamente activa
     */
    public boolean isAccountFullyActive() {
        return isEnabled && isEmailVerified() && isAccountNonLocked && isAccountNonExpired;
    }

    // ===== VALIDACIONES EN SETTERS =====

    /**
     * Previene la modificación del rol después de la creación inicial
     * Solo permite asignar el rol si actualmente es null (creación inicial)
     */
    public void setRole(Role role) {
        if (this.role != null && role != null && !this.role.equals(role)) {
            throw new IllegalStateException("User role cannot be modified after initial assignment");
        }
        this.role = role;
    }

    // ===== BUILDERS PERSONALIZADOS =====

    /**
     * Builder estático para crear un nuevo usuario con rol USER
     */
    public static User createRegularUser(String firstName, String lastName, String email, String password, Role userRole) {
        User user = new User();
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEmail(email);
        user.setPassword(password);
        user.setRole(userRole);
        user.setUserType(UserType.INDIVIDUAL);
        user.setSubscriptionType(SubscriptionType.FREE);
        user.setEnabled(false);
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setCredentialsNonExpired(true);
        return user;
    }

    /**
     * Builder estático para crear un nuevo usuario administrador
     */
    public static User createAdminUser(String firstName, String lastName, String email, String password, Role adminRole) {
        User user = new User();
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEmail(email);
        user.setPassword(password);
        user.setRole(adminRole);
        user.setUserType(UserType.INDIVIDUAL);
        user.setSubscriptionType(SubscriptionType.FREE);
        user.setEnabled(true); // Los admin se crean habilitados por defecto
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setCredentialsNonExpired(true);
        return user;
    }
}