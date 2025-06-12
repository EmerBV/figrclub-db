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
import java.util.Collection;
import java.util.HashSet;

/**
 * Entidad User con lógica consistente:
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
        @Index(name = "idx_user_type", columnList = "user_type")
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

    // ===== RELACIONES =====
    @ManyToMany(
            fetch = FetchType.EAGER,
            cascade = { CascadeType.DETACH, CascadeType.MERGE, CascadeType.PERSIST, CascadeType.REFRESH }
    )
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id")
    )
    @Builder.Default
    private Collection<Role> roles = new HashSet<>();

    // ===== CONSTRUCTORES =====
    public User(String firstName, String lastName, String email, String password) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.password = password;
        this.isEnabled = false;
        // LÓGICA CONSISTENTE: Usuario básico siempre empieza como FREE + INDIVIDUAL
        this.userType = UserType.INDIVIDUAL;
        this.subscriptionType = SubscriptionType.FREE;
    }

    // ===== MÉTODOS DE UTILIDAD =====
    public String getFullName() {
        return firstName + " " + lastName;
    }

    public boolean hasRole(String roleName) {
        return roles.stream()
                .anyMatch(role -> role.getName().equals(roleName));
    }

    public boolean isAdmin() {
        return hasRole("ROLE_ADMIN");
    }

    public boolean isEmailVerified() {
        return isEnabled && emailVerifiedAt != null;
    }

    public void markEmailAsVerified() {
        this.isEnabled = true;
        this.emailVerifiedAt = LocalDateTime.now();
    }

    public void disable() {
        this.isEnabled = false;
    }

    public void enable() {
        this.isEnabled = true;
        if (this.emailVerifiedAt == null) {
            this.emailVerifiedAt = LocalDateTime.now();
        }
    }

    public boolean isAccountFullyActive() {
        return isEnabled &&
                isAccountNonExpired &&
                isAccountNonLocked &&
                isCredentialsNonExpired &&
                emailVerifiedAt != null;
    }

    // ===== MÉTODOS CORREGIDOS PARA SUSCRIPCIONES =====

    /**
     * Verifica si el usuario tiene suscripción PRO
     * PRO siempre implica que es PRO_SELLER
     */
    public boolean isPro() {
        return subscriptionType == SubscriptionType.PRO;
    }

    /**
     * Verifica si el usuario es un vendedor profesional
     * PRO_SELLER siempre implica suscripción PRO
     */
    public boolean isProSeller() {
        return userType == UserType.PRO_SELLER;
    }

    /**
     * Verifica si es usuario básico individual gratuito
     */
    public boolean isFreeIndividual() {
        return userType == UserType.INDIVIDUAL && subscriptionType == SubscriptionType.FREE;
    }

    /**
     * Valida que la combinación de tipo de usuario y suscripción sea consistente
     */
    public boolean isValidUserConfiguration() {
        return (userType == UserType.INDIVIDUAL && subscriptionType == SubscriptionType.FREE) ||
                (userType == UserType.PRO_SELLER && subscriptionType == SubscriptionType.PRO);
    }

    /**
     * ÚNICO MÉTODO DE UPGRADE: Actualiza a vendedor profesional con suscripción PRO
     * FREE + INDIVIDUAL → PRO + PRO_SELLER
     */
    public void upgradeToProSeller(String businessName, String businessDescription,
                                   String fiscalAddress, String taxId, String paymentMethod) {

        // Validar que el usuario actual sea FREE + INDIVIDUAL
        if (!isFreeIndividual()) {
            throw new IllegalStateException("Only FREE INDIVIDUAL users can upgrade to PRO SELLER");
        }

        // Validar datos de negocio requeridos
        if (businessName == null || businessName.trim().isEmpty()) {
            throw new IllegalArgumentException("Business name is required for Pro Seller upgrade");
        }
        if (fiscalAddress == null || fiscalAddress.trim().isEmpty()) {
            throw new IllegalArgumentException("Fiscal address is required for Pro Seller upgrade");
        }
        if (taxId == null || taxId.trim().isEmpty()) {
            throw new IllegalArgumentException("Tax ID is required for Pro Seller upgrade");
        }
        if (paymentMethod == null || paymentMethod.trim().isEmpty()) {
            throw new IllegalArgumentException("Payment method is required for Pro Seller upgrade");
        }

        // Realizar upgrade completo: FREE+INDIVIDUAL → PRO+PRO_SELLER
        this.userType = UserType.PRO_SELLER;
        this.subscriptionType = SubscriptionType.PRO;
        this.businessName = businessName;
        this.businessDescription = businessDescription;
        this.fiscalAddress = fiscalAddress;
        this.taxId = taxId;
        this.paymentMethod = paymentMethod;
        this.upgradedToProAt = LocalDateTime.now();
    }

    /**
     * Actualiza información de contacto adicional
     */
    public void updateContactInfo(String phone, String country, String city, LocalDate birthDate) {
        this.phone = phone;
        this.country = country;
        this.city = city;
        this.birthDate = birthDate;
    }

    /**
     * Actualiza información de negocio (solo para PRO_SELLER)
     */
    public void updateBusinessInfo(String businessName, String businessDescription,
                                   String businessLogoUrl) {
        if (!isProSeller()) {
            throw new IllegalStateException("Only PRO SELLER users can update business information");
        }

        if (businessName != null && !businessName.trim().isEmpty()) {
            this.businessName = businessName;
        }
        this.businessDescription = businessDescription;
        this.businessLogoUrl = businessLogoUrl;
    }

    /**
     * Verifica si puede acceder a funcionalidades PRO
     * Solo los PRO_SELLER verificados pueden acceder
     */
    public boolean canAccessProFeatures() {
        return isProSeller() && isAccountFullyActive();
    }

    /**
     * Obtiene el nombre para mostrar
     */
    public String getDisplayName() {
        if (isProSeller() && businessName != null && !businessName.trim().isEmpty()) {
            return businessName;
        }
        return getFullName();
    }

    /**
     * Verifica si puede actualizar a PRO_SELLER
     */
    public boolean canUpgradeToProSeller() {
        return isFreeIndividual() && isEmailVerified();
    }

    // ===== MÉTODOS PARA VALIDACIÓN EN BASE DE DATOS =====

    @PrePersist
    @PreUpdate
    private void validateUserConfiguration() {
        if (!isValidUserConfiguration()) {
            throw new IllegalStateException(
                    String.format("Invalid user configuration: %s + %s. " +
                                    "Valid combinations: FREE+INDIVIDUAL or PRO+PRO_SELLER",
                            subscriptionType, userType)
            );
        }
    }
}

