package com.figrclub.figrclubdb.domain.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Collection;
import java.util.HashSet;

/**
 * Entidad Role ACTUALIZADA para relación One-to-Many con User
 * Un rol puede tener muchos usuarios, pero cada usuario tiene exactamente un rol
 */
@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "roles", indexes = {
        @Index(name = "idx_role_name", columnList = "name", unique = true)
})
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 50)
    private String name;

    @Column(length = 200)
    private String description;

    // ===== CONSTRUCTORES =====

    public Role(String name) {
        this.name = name;
    }

    public Role(String name, String description) {
        this.name = name;
        this.description = description;
    }

    // ===== RELACIÓN ONE-TO-MANY CON USUARIOS =====

    /**
     * CAMBIO: Relación One-to-Many en lugar de Many-to-Many
     * Un rol puede tener muchos usuarios, pero cada usuario tiene exactamente un rol
     */
    @OneToMany(mappedBy = "role", fetch = FetchType.LAZY, cascade = CascadeType.PERSIST)
    private Collection<User> users = new HashSet<>();

    // ===== MÉTODOS DE UTILIDAD =====

    /**
     * Cuenta el número de usuarios que tienen este rol
     */
    public long getUserCount() {
        return users != null ? users.size() : 0;
    }

    /**
     * Verifica si este es el rol de administrador
     */
    public boolean isAdminRole() {
        return "ROLE_ADMIN".equals(name);
    }

    /**
     * Verifica si este es el rol de usuario regular
     */
    public boolean isUserRole() {
        return "ROLE_USER".equals(name);
    }

    // ===== MÉTODOS ESTÁTICOS PARA ROLES PREDEFINIDOS =====

    /**
     * Crea un rol de administrador
     */
    public static Role createAdminRole() {
        return new Role("ROLE_ADMIN", "Administrator role with full system access");
    }

    /**
     * Crea un rol de usuario regular
     */
    public static Role createUserRole() {
        return new Role("ROLE_USER", "Regular user role with standard access");
    }

    // ===== OVERRIDE METHODS =====

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Role role)) return false;
        return name != null && name.equals(role.name);
    }

    @Override
    public int hashCode() {
        return name != null ? name.hashCode() : 0;
    }

    @Override
    public String toString() {
        return "Role{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", description='" + description + '\'' +
                ", userCount=" + getUserCount() +
                '}';
    }
}