package com.figrclub.figrclubdb.repository;

import com.figrclub.figrclubdb.domain.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.enums.UserType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // ===== MÉTODOS EXISTENTES =====

    /**
     * Verifica si existe un usuario con el email dado
     */
    boolean existsByEmail(String email);

    /**
     * Encuentra un usuario por su email
     */
    User findByEmail(String email);

    /**
     * Encuentra un usuario por email (Optional)
     */
    Optional<User> findOptionalByEmail(String email);

    /**
     * Encuentra todos los usuarios activos
     */
    Page<User> findByIsEnabledTrue(Pageable pageable);

    /**
     * Encuentra todos los usuarios inactivos
     */
    Page<User> findByIsEnabledFalse(Pageable pageable);

    /**
     * Busca usuarios por nombre o apellido (case insensitive)
     */
    @Query("SELECT u FROM User u WHERE " +
            "LOWER(u.firstName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(u.lastName) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    Page<User> findByNameContainingIgnoreCase(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Encuentra usuarios por rol
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = :roleName")
    Page<User> findByRoleName(@Param("roleName") String roleName, Pageable pageable);

    /**
     * Encuentra usuarios creados después de una fecha específica
     */
    @Query("SELECT u FROM User u WHERE u.createdAt >= :date")
    List<User> findUsersCreatedAfter(@Param("date") LocalDateTime date);

    /**
     * Cuenta usuarios activos
     */
    long countByIsEnabledTrue();

    /**
     * Cuenta usuarios por rol
     */
    @Query("SELECT COUNT(u) FROM User u JOIN u.roles r WHERE r.name = :roleName")
    long countByRoleName(@Param("roleName") String roleName);

    // ===== NUEVOS MÉTODOS PARA SUSCRIPCIONES Y TIPOS DE USUARIO =====

    /**
     * Encuentra usuarios por tipo de suscripción
     */
    Page<User> findBySubscriptionType(SubscriptionType subscriptionType, Pageable pageable);

    /**
     * Encuentra usuarios por tipo de usuario
     */
    Page<User> findByUserType(UserType userType, Pageable pageable);

    /**
     * Cuenta usuarios por tipo de suscripción
     */
    long countBySubscriptionType(SubscriptionType subscriptionType);

    /**
     * Cuenta usuarios por tipo de usuario
     */
    long countByUserType(UserType userType);

    /**
     * Encuentra usuarios PRO activos
     */
    @Query("SELECT u FROM User u WHERE u.subscriptionType = :subscriptionType AND u.isEnabled = true")
    Page<User> findActiveUsersBySubscriptionType(@Param("subscriptionType") SubscriptionType subscriptionType, Pageable pageable);

    /**
     * Encuentra vendedores profesionales activos
     */
    @Query("SELECT u FROM User u WHERE u.userType = :userType AND u.isEnabled = true")
    Page<User> findActiveUsersByUserType(@Param("userType") UserType userType, Pageable pageable);

    /**
     * Encuentra usuarios por tipo de suscripción y tipo de usuario
     */
    Page<User> findBySubscriptionTypeAndUserType(SubscriptionType subscriptionType, UserType userType, Pageable pageable);

    /**
     * Cuenta usuarios por tipo de suscripción y tipo de usuario
     */
    long countBySubscriptionTypeAndUserType(SubscriptionType subscriptionType, UserType userType);

    /**
     * Encuentra usuarios que se actualizaron a PRO en un rango de fechas
     */
    @Query("SELECT u FROM User u WHERE u.upgradedToProAt BETWEEN :startDate AND :endDate")
    List<User> findUsersUpgradedToProBetween(@Param("startDate") LocalDateTime startDate,
                                             @Param("endDate") LocalDateTime endDate);

    /**
     * Encuentra vendedores profesionales con información de negocio completa
     */
    @Query("SELECT u FROM User u WHERE u.userType = 'PRO_SELLER' AND " +
            "u.businessName IS NOT NULL AND u.fiscalAddress IS NOT NULL AND u.taxId IS NOT NULL")
    Page<User> findProSellersWithCompleteBusinessInfo(Pageable pageable);

    /**
     * Cuenta vendedores profesionales con información de negocio completa
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.userType = 'PRO_SELLER' AND " +
            "u.businessName IS NOT NULL AND u.fiscalAddress IS NOT NULL AND u.taxId IS NOT NULL")
    long countProSellersWithCompleteBusinessInfo();

    /**
     * Encuentra usuarios por país
     */
    Page<User> findByCountry(String country, Pageable pageable);

    /**
     * Encuentra usuarios por ciudad
     */
    Page<User> findByCity(String city, Pageable pageable);

    /**
     * Busca usuarios por nombre comercial (case insensitive)
     */
    @Query("SELECT u FROM User u WHERE u.userType = 'PRO_SELLER' AND " +
            "LOWER(u.businessName) LIKE LOWER(CONCAT('%', :businessName, '%'))")
    Page<User> findByBusinessNameContainingIgnoreCase(@Param("businessName") String businessName, Pageable pageable);

    /**
     * Encuentra usuarios con información de contacto completa
     */
    @Query("SELECT u FROM User u WHERE u.phone IS NOT NULL AND u.country IS NOT NULL AND u.city IS NOT NULL")
    Page<User> findUsersWithCompleteContactInfo(Pageable pageable);

    /**
     * Cuenta usuarios con información de contacto completa
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.phone IS NOT NULL AND u.country IS NOT NULL AND u.city IS NOT NULL")
    long countUsersWithCompleteContactInfo();

    /**
     * Encuentra usuarios por método de pago
     */
    @Query("SELECT u FROM User u WHERE u.paymentMethod = :paymentMethod")
    Page<User> findByPaymentMethod(@Param("paymentMethod") String paymentMethod, Pageable pageable);

    /**
     * Estadísticas de conversión a PRO por mes
     */
    @Query("SELECT YEAR(u.upgradedToProAt) as year, MONTH(u.upgradedToProAt) as month, COUNT(u) as count " +
            "FROM User u WHERE u.upgradedToProAt IS NOT NULL " +
            "GROUP BY YEAR(u.upgradedToProAt), MONTH(u.upgradedToProAt) " +
            "ORDER BY year DESC, month DESC")
    List<Object[]> getProUpgradeStatsByMonth();

    /**
     * Estadísticas de usuarios por país
     */
    @Query("SELECT u.country, COUNT(u) as count FROM User u WHERE u.country IS NOT NULL " +
            "GROUP BY u.country ORDER BY count DESC")
    List<Object[]> getUserStatsByCountry();

    /**
     * Encuentra usuarios que pueden actualizar a PRO (FREE y email verificado)
     */
    @Query("SELECT u FROM User u WHERE u.subscriptionType = 'FREE' AND u.isEnabled = true AND u.emailVerifiedAt IS NOT NULL")
    Page<User> findUsersEligibleForProUpgrade(Pageable pageable);

    /**
     * Cuenta usuarios que pueden actualizar a PRO
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.subscriptionType = 'FREE' AND u.isEnabled = true AND u.emailVerifiedAt IS NOT NULL")
    long countUsersEligibleForProUpgrade();

    /**
     * Busca usuarios por múltiples criterios
     */
    @Query("SELECT u FROM User u WHERE " +
            "(:subscriptionType IS NULL OR u.subscriptionType = :subscriptionType) AND " +
            "(:userType IS NULL OR u.userType = :userType) AND " +
            "(:enabled IS NULL OR u.isEnabled = :enabled) AND " +
            "(:country IS NULL OR u.country = :country) AND " +
            "(:searchTerm IS NULL OR " +
            " LOWER(u.firstName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            " LOWER(u.lastName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            " LOWER(u.email) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            " LOWER(u.businessName) LIKE LOWER(CONCAT('%', :searchTerm, '%')))")
    Page<User> findUsersWithFilters(@Param("subscriptionType") SubscriptionType subscriptionType,
                                    @Param("userType") UserType userType,
                                    @Param("enabled") Boolean enabled,
                                    @Param("country") String country,
                                    @Param("searchTerm") String searchTerm,
                                    Pageable pageable);

    /**
     * Encuentra vendedores profesionales por Tax ID
     */
    @Query("SELECT u FROM User u WHERE u.userType = 'PRO_SELLER' AND u.taxId = :taxId")
    Optional<User> findProSellerByTaxId(@Param("taxId") String taxId);

    /**
     * Verifica si existe un Tax ID registrado
     */
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM User u WHERE u.taxId = :taxId")
    boolean existsByTaxId(@Param("taxId") String taxId);
}
