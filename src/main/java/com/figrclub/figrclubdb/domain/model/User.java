package com.figrclub.figrclubdb.domain.model;

import com.figrclub.figrclubdb.domain.base.Auditable;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.hibernate.annotations.NaturalId;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;

/**
 * Entidad User actualizada con soporte para verificación de email
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
        @Index(name = "idx_user_email_verified", columnList = "email_verified_at")
})
public class User extends Auditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

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

    /**
     * isEnabled ahora controla si el usuario ha verificado su email
     * false = email no verificado, true = email verificado
     */
    @Builder.Default
    @Column(name = "is_enabled", nullable = false)
    private boolean isEnabled = false; // Cambiado a false por defecto para requerir verificación

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

    public User(String firstName, String lastName, String email, String password) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.password = password;
        this.isEnabled = false; // Usuario debe verificar email
    }

    public String getFullName() {
        return firstName + " " + lastName;
    }

    /**
     * Verifica si el usuario tiene un rol específico
     */
    public boolean hasRole(String roleName) {
        return roles.stream()
                .anyMatch(role -> role.getName().equals(roleName));
    }

    /**
     * Verifica si el usuario es administrador
     */
    public boolean isAdmin() {
        return hasRole("ROLE_ADMIN");
    }

    /**
     * Verifica si el email está verificado
     */
    public boolean isEmailVerified() {
        return isEnabled && emailVerifiedAt != null;
    }

    /**
     * Marca el email como verificado
     */
    public void markEmailAsVerified() {
        this.isEnabled = true;
        this.emailVerifiedAt = LocalDateTime.now();
    }

    /**
     * Deshabilita el usuario (para casos administrativos)
     */
    public void disable() {
        this.isEnabled = false;
    }

    /**
     * Habilita el usuario (para casos administrativos)
     */
    public void enable() {
        this.isEnabled = true;
        if (this.emailVerifiedAt == null) {
            this.emailVerifiedAt = LocalDateTime.now();
        }
    }

    /**
     * Verifica si la cuenta está completamente activa
     * (email verificado y no bloqueada/expirada)
     */
    public boolean isAccountFullyActive() {
        return isEnabled &&
                isAccountNonExpired &&
                isAccountNonLocked &&
                isCredentialsNonExpired &&
                emailVerifiedAt != null;
    }
}

