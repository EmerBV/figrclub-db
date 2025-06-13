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

import java.util.List;
import java.util.Optional;

/**
 * Repositorio de usuarios CORREGIDO con funcionalidad completa de roles y tiers
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // ===== MÉTODOS BÁSICOS DE BÚSQUEDA =====

    /**
     * Encuentra un usuario por email
     */
    User findByEmail(String email);

    /**
     * Encuentra un usuario por email (Optional)
     */
    Optional<User> findOptionalByEmail(String email);

    /**
     * Verifica si existe un usuario con el email dado
     */
    boolean existsByEmail(String email);

    // ===== MÉTODOS POR ESTADO DE ACTIVACIÓN =====

    /**
     * Encuentra usuarios activos (habilitados)
     */
    Page<User> findByIsEnabledTrue(Pageable pageable);

    /**
     * Encuentra usuarios inactivos (deshabilitados)
     */
    Page<User> findByIsEnabledFalse(Pageable pageable);

    /**
     * Cuenta usuarios activos
     */
    long countByIsEnabledTrue();

    /**
     * Cuenta usuarios inactivos
     */
    long countByIsEnabledFalse();

    // ===== MÉTODOS DE ROLES CORREGIDOS/AÑADIDOS =====

    /**
     * Encuentra usuarios por nombre de rol
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = :roleName")
    Page<User> findByRoleName(@Param("roleName") String roleName, Pageable pageable);

    /**
     * Cuenta usuarios por nombre de rol
     */
    @Query("SELECT COUNT(u) FROM User u JOIN u.roles r WHERE r.name = :roleName")
    long countByRoleName(@Param("roleName") String roleName);

    /**
     * Verifica si un usuario tiene un rol específico
     */
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END " +
            "FROM User u JOIN u.roles r WHERE u.id = :userId AND r.name = :roleName")
    boolean userHasRole(@Param("userId") Long userId, @Param("roleName") String roleName);

    // ===== MÉTODOS CORREGIDOS POR TIPO DE USUARIO =====

    /**
     * Encuentra usuarios por tipo de usuario
     */
    Page<User> findByUserType(UserType userType, Pageable pageable);

    /**
     * Cuenta usuarios por tipo de usuario
     */
    long countByUserType(UserType userType);

    // ===== MÉTODOS CORREGIDOS POR SUSCRIPCIÓN =====

    /**
     * Encuentra usuarios por tipo de suscripción
     */
    Page<User> findBySubscriptionType(SubscriptionType subscriptionType, Pageable pageable);

    /**
     * Cuenta usuarios por tipo de suscripción
     */
    long countBySubscriptionType(SubscriptionType subscriptionType);

    // ===== MÉTODOS COMBINADOS: ROLES + TIERS =====

    /**
     * Encuentra administradores que son PRO_SELLER
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = 'ROLE_ADMIN' AND u.userType = 'PRO_SELLER'")
    Page<User> findAdminProSellers(Pageable pageable);

    /**
     * Cuenta administradores que son PRO_SELLER
     */
    @Query("SELECT COUNT(u) FROM User u JOIN u.roles r WHERE r.name = 'ROLE_ADMIN' AND u.userType = 'PRO_SELLER'")
    long countAdminProSellers();

    /**
     * Encuentra usuarios regulares que son PRO_SELLER
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = 'ROLE_USER' AND u.userType = 'PRO_SELLER' " +
            "AND NOT EXISTS (SELECT 1 FROM User u2 JOIN u2.roles r2 WHERE u2.id = u.id AND r2.name = 'ROLE_ADMIN')")
    Page<User> findRegularProSellers(Pageable pageable);

    /**
     * Cuenta usuarios regulares que son PRO_SELLER
     */
    @Query("SELECT COUNT(u) FROM User u JOIN u.roles r WHERE r.name = 'ROLE_USER' AND u.userType = 'PRO_SELLER' " +
            "AND NOT EXISTS (SELECT 1 FROM User u2 JOIN u2.roles r2 WHERE u2.id = u.id AND r2.name = 'ROLE_ADMIN')")
    long countRegularProSellers();

    /**
     * Encuentra administradores que son usuarios básicos (INDIVIDUAL)
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = 'ROLE_ADMIN' AND u.userType = 'INDIVIDUAL'")
    Page<User> findAdminBasicUsers(Pageable pageable);

    /**
     * Cuenta administradores que son usuarios básicos (INDIVIDUAL)
     */
    @Query("SELECT COUNT(u) FROM User u JOIN u.roles r WHERE r.name = 'ROLE_ADMIN' AND u.userType = 'INDIVIDUAL'")
    long countAdminBasicUsers();

    /**
     * Cuenta usuarios regulares que son básicos (INDIVIDUAL)
     */
    @Query("SELECT COUNT(u) FROM User u JOIN u.roles r WHERE r.name = 'ROLE_USER' AND u.userType = 'INDIVIDUAL' " +
            "AND NOT EXISTS (SELECT 1 FROM User u2 JOIN u2.roles r2 WHERE u2.id = u.id AND r2.name = 'ROLE_ADMIN')")
    long countRegularBasicUsers();

    // ===== MÉTODOS PARA VALIDACIÓN DE CONFIGURACIONES =====

    /**
     * Encuentra usuarios con una combinación específica de suscripción y tipo de usuario
     */
    Page<User> findBySubscriptionTypeAndUserType(
            SubscriptionType subscriptionType,
            UserType userType,
            Pageable pageable);

    /**
     * Cuenta usuarios con una combinación específica de suscripción y tipo de usuario
     */
    long countBySubscriptionTypeAndUserType(
            SubscriptionType subscriptionType,
            UserType userType);

    // ===== MÉTODOS DE BÚSQUEDA POR NOMBRE =====

    /**
     * Busca usuarios por nombre o apellido (ignorando mayúsculas/minúsculas)
     */
    @Query("SELECT u FROM User u WHERE " +
            "LOWER(u.firstName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(u.lastName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(CONCAT(u.firstName, ' ', u.lastName)) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(u.businessName) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    Page<User> findByNameContainingIgnoreCase(@Param("searchTerm") String searchTerm, Pageable pageable);

    // ===== MÉTODOS DE ESTADÍSTICAS AVANZADAS =====

    /**
     * Cuenta usuarios verificados (activos)
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.isEnabled = true AND u.emailVerifiedAt IS NOT NULL")
    long countVerifiedUsers();

    /**
     * Cuenta usuarios no verificados
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.isEnabled = false OR u.emailVerifiedAt IS NULL")
    long countUnverifiedUsers();

    /**
     * Encuentra usuarios PRO con datos de negocio completos
     */
    @Query("SELECT u FROM User u WHERE " +
            "u.userType = 'PRO_SELLER' AND " +
            "u.subscriptionType = 'PRO' AND " +
            "u.businessName IS NOT NULL AND " +
            "u.fiscalAddress IS NOT NULL AND " +
            "u.taxId IS NOT NULL AND " +
            "u.paymentMethod IS NOT NULL")
    Page<User> findProSellersWithCompleteBusinessData(Pageable pageable);

    /**
     * Encuentra usuarios PRO con datos de negocio incompletos
     */
    @Query("SELECT u FROM User u WHERE " +
            "u.userType = 'PRO_SELLER' AND " +
            "u.subscriptionType = 'PRO' AND " +
            "(u.businessName IS NULL OR " +
            "u.fiscalAddress IS NULL OR " +
            "u.taxId IS NULL OR " +
            "u.paymentMethod IS NULL)")
    Page<User> findProSellersWithIncompleteBusinessData(Pageable pageable);

    // ===== MÉTODOS PARA DIAGNÓSTICOS =====

    /**
     * Encuentra usuarios con configuraciones inválidas
     * Solo deberían existir: FREE+INDIVIDUAL y PRO+PRO_SELLER
     */
    @Query("SELECT u FROM User u WHERE NOT (" +
            "(u.subscriptionType = 'FREE' AND u.userType = 'INDIVIDUAL') OR " +
            "(u.subscriptionType = 'PRO' AND u.userType = 'PRO_SELLER')" +
            ")")
    Page<User> findUsersWithInvalidConfigurations(Pageable pageable);

    /**
     * Cuenta usuarios con configuraciones inválidas
     */
    @Query("SELECT COUNT(u) FROM User u WHERE NOT (" +
            "(u.subscriptionType = 'FREE' AND u.userType = 'INDIVIDUAL') OR " +
            "(u.subscriptionType = 'PRO' AND u.userType = 'PRO_SELLER')" +
            ")")
    long countUsersWithInvalidConfigurations();

    /**
     * Encuentra usuarios INDIVIDUAL que tienen datos de negocio (inconsistencia)
     */
    @Query("SELECT u FROM User u WHERE " +
            "u.userType = 'INDIVIDUAL' AND " +
            "(u.businessName IS NOT NULL OR " +
            "u.fiscalAddress IS NOT NULL OR " +
            "u.taxId IS NOT NULL OR " +
            "u.paymentMethod IS NOT NULL)")
    Page<User> findIndividualUsersWithBusinessData(Pageable pageable);

    /**
     * Cuenta usuarios INDIVIDUAL con datos de negocio
     */
    @Query("SELECT COUNT(u) FROM User u WHERE " +
            "u.userType = 'INDIVIDUAL' AND " +
            "(u.businessName IS NOT NULL OR " +
            "u.fiscalAddress IS NOT NULL OR " +
            "u.taxId IS NOT NULL OR " +
            "u.paymentMethod IS NOT NULL)")
    long countIndividualUsersWithBusinessData();

    // ===== MÉTODOS DE BÚSQUEDA AVANZADA =====

    /**
     * Busca usuarios por criterios múltiples
     */
    @Query("SELECT u FROM User u WHERE " +
            "(:email IS NULL OR LOWER(u.email) LIKE LOWER(CONCAT('%', :email, '%'))) AND " +
            "(:userType IS NULL OR u.userType = :userType) AND " +
            "(:subscriptionType IS NULL OR u.subscriptionType = :subscriptionType) AND " +
            "(:isEnabled IS NULL OR u.isEnabled = :isEnabled)")
    Page<User> findUsersByCriteria(
            @Param("email") String email,
            @Param("userType") UserType userType,
            @Param("subscriptionType") SubscriptionType subscriptionType,
            @Param("isEnabled") Boolean isEnabled,
            Pageable pageable);

    /**
     * Busca usuarios por criterios múltiples incluyendo roles
     */
    @Query("SELECT DISTINCT u FROM User u LEFT JOIN u.roles r WHERE " +
            "(:email IS NULL OR LOWER(u.email) LIKE LOWER(CONCAT('%', :email, '%'))) AND " +
            "(:userType IS NULL OR u.userType = :userType) AND " +
            "(:subscriptionType IS NULL OR u.subscriptionType = :subscriptionType) AND " +
            "(:isEnabled IS NULL OR u.isEnabled = :isEnabled) AND " +
            "(:roleName IS NULL OR r.name = :roleName)")
    Page<User> findUsersByCriteriaWithRole(
            @Param("email") String email,
            @Param("userType") UserType userType,
            @Param("subscriptionType") SubscriptionType subscriptionType,
            @Param("isEnabled") Boolean isEnabled,
            @Param("roleName") String roleName,
            Pageable pageable);

    /**
     * Encuentra usuarios que pueden upgradear a PRO_SELLER
     * (FREE+INDIVIDUAL y email verificado)
     */
    @Query("SELECT u FROM User u WHERE " +
            "u.subscriptionType = 'FREE' AND " +
            "u.userType = 'INDIVIDUAL' AND " +
            "u.isEnabled = true AND " +
            "u.emailVerifiedAt IS NOT NULL")
    Page<User> findUsersEligibleForProSellerUpgrade(Pageable pageable);

    /**
     * Cuenta usuarios elegibles para upgrade a PRO_SELLER
     */
    @Query("SELECT COUNT(u) FROM User u WHERE " +
            "u.subscriptionType = 'FREE' AND " +
            "u.userType = 'INDIVIDUAL' AND " +
            "u.isEnabled = true AND " +
            "u.emailVerifiedAt IS NOT NULL")
    long countUsersEligibleForProSellerUpgrade();

    // ===== MÉTODOS DE ESTADÍSTICAS POR ROLES =====

    /**
     * Encuentra administradores elegibles para upgrade a PRO_SELLER
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE " +
            "r.name = 'ROLE_ADMIN' AND " +
            "u.subscriptionType = 'FREE' AND " +
            "u.userType = 'INDIVIDUAL' AND " +
            "u.isEnabled = true AND " +
            "u.emailVerifiedAt IS NOT NULL")
    Page<User> findAdminUsersEligibleForProSellerUpgrade(Pageable pageable);

    /**
     * Encuentra usuarios regulares elegibles para upgrade a PRO_SELLER
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE " +
            "r.name = 'ROLE_USER' AND " +
            "u.subscriptionType = 'FREE' AND " +
            "u.userType = 'INDIVIDUAL' AND " +
            "u.isEnabled = true AND " +
            "u.emailVerifiedAt IS NOT NULL AND " +
            "NOT EXISTS (SELECT 1 FROM User u2 JOIN u2.roles r2 WHERE u2.id = u.id AND r2.name = 'ROLE_ADMIN')")
    Page<User> findRegularUsersEligibleForProSellerUpgrade(Pageable pageable);

    // ===== MÉTODOS PARA GESTIÓN DE ROLES AVANZADA =====

    /**
     * Encuentra usuarios que solo tienen un rol específico
     */
    @Query("SELECT u FROM User u WHERE " +
            "SIZE(u.roles) = 1 AND " +
            "EXISTS (SELECT 1 FROM User u2 JOIN u2.roles r WHERE u2.id = u.id AND r.name = :roleName)")
    Page<User> findUsersWithOnlyRole(@Param("roleName") String roleName, Pageable pageable);

    /**
     * Encuentra usuarios con múltiples roles
     */
    @Query("SELECT u FROM User u WHERE SIZE(u.roles) > 1")
    Page<User> findUsersWithMultipleRoles(Pageable pageable);

    /**
     * Cuenta usuarios con múltiples roles
     */
    @Query("SELECT COUNT(u) FROM User u WHERE SIZE(u.roles) > 1")
    long countUsersWithMultipleRoles();

    /**
     * Encuentra usuarios sin roles asignados (huérfanos)
     */
    @Query("SELECT u FROM User u WHERE SIZE(u.roles) = 0")
    Page<User> findUsersWithoutRoles(Pageable pageable);

    /**
     * Cuenta usuarios sin roles asignados
     */
    @Query("SELECT COUNT(u) FROM User u WHERE SIZE(u.roles) = 0")
    long countUsersWithoutRoles();

    // ===== MÉTODOS DE REPORTES COMBINADOS =====

    /**
     * Obtiene distribución de usuarios por rol y tipo
     */
    @Query("SELECT r.name, u.userType, u.subscriptionType, COUNT(u) " +
            "FROM User u JOIN u.roles r " +
            "GROUP BY r.name, u.userType, u.subscriptionType " +
            "ORDER BY r.name, u.userType, u.subscriptionType")
    List<Object[]> getUserDistributionByRoleAndType();

    /**
     * Obtiene estadísticas de actividad por rol
     */
    @Query("SELECT r.name, " +
            "COUNT(u), " +
            "SUM(CASE WHEN u.isEnabled = true THEN 1 ELSE 0 END), " +
            "SUM(CASE WHEN u.emailVerifiedAt IS NOT NULL THEN 1 ELSE 0 END) " +
            "FROM User u JOIN u.roles r " +
            "GROUP BY r.name " +
            "ORDER BY r.name")
    List<Object[]> getActivityStatsByRole();

    /**
     * Encuentra los últimos usuarios registrados por rol
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = :roleName " +
            "ORDER BY u.createdAt DESC")
    Page<User> findLatestUsersByRole(@Param("roleName") String roleName, Pageable pageable);

    /**
     * Encuentra usuarios activos por rol y período
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE " +
            "r.name = :roleName AND " +
            "u.isEnabled = true AND " +
            "u.emailVerifiedAt IS NOT NULL AND " +
            "u.createdAt >= :since " +
            "ORDER BY u.createdAt DESC")
    Page<User> findActiveUsersByRoleSince(@Param("roleName") String roleName,
                                          @Param("since") java.time.LocalDateTime since,
                                          Pageable pageable);

    // ===== MÉTODOS DE VALIDACIÓN DE SEGURIDAD =====

    /**
     * Verifica si el usuario es el último administrador del sistema
     */
    @Query("SELECT CASE WHEN COUNT(u) = 1 THEN true ELSE false END " +
            "FROM User u JOIN u.roles r WHERE r.name = 'ROLE_ADMIN' AND u.id = :userId")
    boolean isLastAdmin(@Param("userId") Long userId);

    /**
     * Encuentra administradores activos (verificados y habilitados)
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE " +
            "r.name = 'ROLE_ADMIN' AND " +
            "u.isEnabled = true AND " +
            "u.emailVerifiedAt IS NOT NULL")
    Page<User> findActiveAdmins(Pageable pageable);

    /**
     * Cuenta administradores activos
     */
    @Query("SELECT COUNT(u) FROM User u JOIN u.roles r WHERE " +
            "r.name = 'ROLE_ADMIN' AND " +
            "u.isEnabled = true AND " +
            "u.emailVerifiedAt IS NOT NULL")
    long countActiveAdmins();
}
