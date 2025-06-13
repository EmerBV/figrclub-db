package com.figrclub.figrclubdb.repository;

import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.enums.UserType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Repositorio de usuarios ACTUALIZADO para trabajar con rol único
 * Todas las consultas ahora usan la relación ManyToOne con Role
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // ===== MÉTODOS BÁSICOS =====

    /**
     * Busca un usuario por email
     */
    User findByEmail(String email);

    /**
     * Verifica si existe un usuario con el email dado
     */
    boolean existsByEmail(String email);

    // ===== MÉTODOS DE BÚSQUEDA POR CONTENIDO =====

    /**
     * Busca usuarios por email, nombre o apellido (case insensitive)
     */
    Page<User> findByEmailContainingIgnoreCaseOrFirstNameContainingIgnoreCaseOrLastNameContainingIgnoreCase(
            String email, String firstName, String lastName, Pageable pageable);

    // ===== MÉTODOS POR ESTADO DE CUENTA =====

    /**
     * Encuentra usuarios activos (habilitados y verificados)
     */
    Page<User> findByIsEnabledTrueAndEmailVerifiedAtIsNotNull(Pageable pageable);

    /**
     * Encuentra usuarios verificados
     */
    Page<User> findByEmailVerifiedAtIsNotNull(Pageable pageable);

    /**
     * Encuentra usuarios no verificados
     */
    Page<User> findByEmailVerifiedAtIsNull(Pageable pageable);

    /**
     * Cuenta usuarios activos (habilitados y verificados)
     */
    long countByIsEnabledTrueAndEmailVerifiedAtIsNotNull();

    /**
     * Cuenta usuarios verificados
     */
    long countByEmailVerifiedAtIsNotNull();

    // ===== MÉTODOS POR ROL ÚNICO =====

    /**
     * Encuentra usuarios por nombre de rol
     */
    @Query("SELECT u FROM User u WHERE u.role.name = :roleName")
    Page<User> findByRoleName(@Param("roleName") String roleName, Pageable pageable);

    /**
     * Cuenta usuarios por nombre de rol
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.role.name = :roleName")
    long countByRoleName(@Param("roleName") String roleName);

    /**
     * Encuentra usuarios administradores
     */
    @Query("SELECT u FROM User u WHERE u.role.name = 'ROLE_ADMIN'")
    Page<User> findAdminUsers(Pageable pageable);

    /**
     * Encuentra usuarios regulares (no admin)
     */
    @Query("SELECT u FROM User u WHERE u.role.name = 'ROLE_USER'")
    Page<User> findRegularUsers(Pageable pageable);

    // ===== MÉTODOS POR TIPO DE USUARIO =====

    /**
     * Encuentra usuarios por tipo de usuario
     */
    Page<User> findByUserType(UserType userType, Pageable pageable);

    /**
     * Cuenta usuarios por tipo de usuario
     */
    long countByUserType(UserType userType);

    // ===== MÉTODOS POR SUSCRIPCIÓN =====

    /**
     * Encuentra usuarios por tipo de suscripción
     */
    Page<User> findBySubscriptionType(SubscriptionType subscriptionType, Pageable pageable);

    /**
     * Cuenta usuarios por tipo de suscripción
     */
    long countBySubscriptionType(SubscriptionType subscriptionType);

    /**
     * Cuenta usuarios por tipo de usuario y suscripción
     */
    long countByUserTypeAndSubscriptionType(UserType userType, SubscriptionType subscriptionType);

    // ===== MÉTODOS COMBINADOS: ROLES + TIERS =====

    /**
     * Encuentra administradores que son PRO_SELLER
     */
    @Query("SELECT u FROM User u WHERE u.role.name = 'ROLE_ADMIN' AND u.userType = 'PRO_SELLER'")
    Page<User> findAdminProSellers(Pageable pageable);

    /**
     * Cuenta administradores que son PRO_SELLER
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.role.name = 'ROLE_ADMIN' AND u.userType = 'PRO_SELLER'")
    long countAdminProSellers();

    /**
     * Encuentra usuarios regulares que son PRO_SELLER
     */
    @Query("SELECT u FROM User u WHERE u.role.name = 'ROLE_USER' AND u.userType = 'PRO_SELLER'")
    Page<User> findRegularProSellers(Pageable pageable);

    /**
     * Cuenta usuarios regulares que son PRO_SELLER
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.role.name = 'ROLE_USER' AND u.userType = 'PRO_SELLER'")
    long countRegularProSellers();

    /**
     * Encuentra administradores que son usuarios básicos (INDIVIDUAL)
     */
    @Query("SELECT u FROM User u WHERE u.role.name = 'ROLE_ADMIN' AND u.userType = 'INDIVIDUAL'")
    Page<User> findAdminBasicUsers(Pageable pageable);

    /**
     * Cuenta administradores que son usuarios básicos (INDIVIDUAL)
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.role.name = 'ROLE_ADMIN' AND u.userType = 'INDIVIDUAL'")
    long countAdminBasicUsers();

    /**
     * Encuentra usuarios regulares que son usuarios básicos (INDIVIDUAL)
     */
    @Query("SELECT u FROM User u WHERE u.role.name = 'ROLE_USER' AND u.userType = 'INDIVIDUAL'")
    Page<User> findRegularBasicUsers(Pageable pageable);

    /**
     * Cuenta usuarios regulares que son usuarios básicos (INDIVIDUAL)
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.role.name = 'ROLE_USER' AND u.userType = 'INDIVIDUAL'")
    long countRegularBasicUsers();

    // ===== MÉTODOS DE ELEGIBILIDAD PARA UPGRADE =====

    /**
     * Encuentra usuarios elegibles para upgrade a PRO_SELLER
     */
    @Query("SELECT u FROM User u WHERE " +
            "u.subscriptionType = 'FREE' AND " +
            "u.userType = 'INDIVIDUAL' AND " +
            "u.isEnabled = true AND " +
            "u.emailVerifiedAt IS NOT NULL")
    Page<User> findUsersEligibleForProSellerUpgrade(Pageable pageable);

    /**
     * Encuentra administradores elegibles para upgrade a PRO_SELLER
     */
    @Query("SELECT u FROM User u WHERE " +
            "u.role.name = 'ROLE_ADMIN' AND " +
            "u.subscriptionType = 'FREE' AND " +
            "u.userType = 'INDIVIDUAL' AND " +
            "u.isEnabled = true AND " +
            "u.emailVerifiedAt IS NOT NULL")
    Page<User> findAdminUsersEligibleForProSellerUpgrade(Pageable pageable);

    /**
     * Encuentra usuarios regulares elegibles para upgrade a PRO_SELLER
     */
    @Query("SELECT u FROM User u WHERE " +
            "u.role.name = 'ROLE_USER' AND " +
            "u.subscriptionType = 'FREE' AND " +
            "u.userType = 'INDIVIDUAL' AND " +
            "u.isEnabled = true AND " +
            "u.emailVerifiedAt IS NOT NULL")
    Page<User> findRegularUsersEligibleForProSellerUpgrade(Pageable pageable);

    // ===== MÉTODOS DE BÚSQUEDA AVANZADA =====

    /**
     * Búsqueda combinada por rol, tipo de usuario y suscripción
     */
    @Query("SELECT u FROM User u WHERE " +
            "(:roleName IS NULL OR u.role.name = :roleName) AND " +
            "(:userType IS NULL OR u.userType = :userType) AND " +
            "(:subscriptionType IS NULL OR u.subscriptionType = :subscriptionType)")
    Page<User> findByAdvancedFilters(
            @Param("roleName") String roleName,
            @Param("userType") UserType userType,
            @Param("subscriptionType") SubscriptionType subscriptionType,
            Pageable pageable);

    /**
     * Búsqueda combinada por rol, tipo de usuario, suscripción y estado activo
     */
    @Query("SELECT u FROM User u WHERE " +
            "(:roleName IS NULL OR u.role.name = :roleName) AND " +
            "(:userType IS NULL OR u.userType = :userType) AND " +
            "(:subscriptionType IS NULL OR u.subscriptionType = :subscriptionType) AND " +
            "(:activeOnly = false OR (u.isEnabled = true AND u.emailVerifiedAt IS NOT NULL))")
    Page<User> findByAdvancedFiltersWithActiveStatus(
            @Param("roleName") String roleName,
            @Param("userType") UserType userType,
            @Param("subscriptionType") SubscriptionType subscriptionType,
            @Param("activeOnly") boolean activeOnly,
            Pageable pageable);

    // ===== MÉTODOS DE REPORTES Y ESTADÍSTICAS =====

    /**
     * Obtiene distribución de usuarios por rol y tipo
     */
    @Query("SELECT u.role.name, u.userType, u.subscriptionType, COUNT(u) " +
            "FROM User u " +
            "GROUP BY u.role.name, u.userType, u.subscriptionType " +
            "ORDER BY u.role.name, u.userType, u.subscriptionType")
    Object[] getUserDistributionStats();

    /**
     * Cuenta usuarios por rol y estado de verificación
     */
    @Query("SELECT u.role.name, " +
            "SUM(CASE WHEN u.emailVerifiedAt IS NOT NULL THEN 1 ELSE 0 END) as verified, " +
            "SUM(CASE WHEN u.emailVerifiedAt IS NULL THEN 1 ELSE 0 END) as unverified " +
            "FROM User u " +
            "GROUP BY u.role.name")
    Object[] getUserVerificationStatsByRole();

    /**
     * Cuenta usuarios activos por rol
     */
    @Query("SELECT u.role.name, COUNT(u) " +
            "FROM User u " +
            "WHERE u.isEnabled = true AND u.emailVerifiedAt IS NOT NULL " +
            "GROUP BY u.role.name")
    Object[] getActiveUsersByRole();

    // ===== MÉTODOS PARA VALIDACIONES DE SEGURIDAD =====

    /**
     * Verifica si un usuario existe con un rol específico
     */
    @Query("SELECT COUNT(u) > 0 FROM User u WHERE u.id = :userId AND u.role.name = :roleName")
    boolean userExistsWithRole(@Param("userId") Long userId, @Param("roleName") String roleName);

    /**
     * Encuentra usuarios creados en un rango de fechas por rol
     */
    @Query("SELECT u FROM User u WHERE " +
            "u.role.name = :roleName AND " +
            "u.createdAt BETWEEN :startDate AND :endDate")
    Page<User> findUsersByRoleAndDateRange(
            @Param("roleName") String roleName,
            @Param("startDate") java.time.LocalDateTime startDate,
            @Param("endDate") java.time.LocalDateTime endDate,
            Pageable pageable);

    /**
     * Cuenta el total de administradores en el sistema
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.role.name = 'ROLE_ADMIN'")
    long countTotalAdmins();

    /**
     * Verifica si queda al menos un administrador activo (para prevenir bloqueo del sistema)
     */
    @Query("SELECT COUNT(u) > 0 FROM User u WHERE " +
            "u.role.name = 'ROLE_ADMIN' AND " +
            "u.isEnabled = true AND " +
            "u.emailVerifiedAt IS NOT NULL AND " +
            "u.isAccountNonLocked = true")
    boolean hasActiveAdmins();
}