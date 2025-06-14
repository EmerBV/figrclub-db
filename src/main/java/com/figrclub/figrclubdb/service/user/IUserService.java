package com.figrclub.figrclubdb.service.user;

import com.figrclub.figrclubdb.domain.model.Role;
import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.enums.UserType;
import com.figrclub.figrclubdb.request.CreateUserRequest;
import com.figrclub.figrclubdb.request.UpdateContactInfoRequest;
import com.figrclub.figrclubdb.request.UpdateBusinessInfoRequest;
import com.figrclub.figrclubdb.request.UpgradeToProSellerRequest;
import com.figrclub.figrclubdb.request.UserUpdateRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Interface del servicio de usuarios ACTUALIZADA:
 * - Los roles son inmutables: se asignan solo durante la creación del usuario
 * - Se eliminan todos los métodos de modificación de roles
 * - Se mantiene la funcionalidad de consulta y gestión de usuarios
 * - Lógica consistente de tiers: FREE+INDIVIDUAL y PRO+PRO_SELLER
 */
public interface IUserService {

    // ===== MÉTODOS DE BÚSQUEDA BÁSICA =====

    User getUserById(Long userId);

    /**
     * Encuentra un usuario por su email
     * @param email Email del usuario
     * @return Optional con el usuario si existe
     */
    Optional<User> findByEmail(String email);

    /**
     * Verifica si existe un usuario con el email dado
     * @param email Email a verificar
     * @return true si existe, false en caso contrario
     */
    boolean existsByEmail(String email);

    /**
     * Busca usuarios por nombre o email
     * @param searchTerm Término de búsqueda
     * @param pageable Información de paginación
     * @return Página de usuarios que coinciden con la búsqueda
     */
    Page<User> searchUsers(String searchTerm, Pageable pageable);

    // ===== MÉTODOS DE LISTADO CON PAGINACIÓN =====

    /**
     * Encuentra todos los usuarios con paginación
     * @param pageable Información de paginación
     * @return Página de todos los usuarios
     */
    Page<User> findAllUsers(Pageable pageable);

    /**
     * Encuentra usuarios regulares verificados y activos
     */
    Page<User> findVerifiedRegularUsers(Pageable pageable);

    /**
     * Encuentra usuarios públicos (verificados, activos, no-admins)
     */
    Page<User> findPublicUsers(Pageable pageable, UserType userType, SubscriptionType subscriptionType);

    /**
     * Cuenta usuarios públicos
     */
    long countPublicUsers();

    /**
     * Encuentra todos los usuarios activos (verificados) con paginación
     * @param pageable Información de paginación
     * @return Página de usuarios activos
     */
    Page<User> findActiveUsers(Pageable pageable);

    /**
     * Encuentra todos los usuarios verificados con paginación
     * @param pageable Información de paginación
     * @return Página de usuarios verificados
     */
    Page<User> findVerifiedUsers(Pageable pageable);

    /**
     * Encuentra todos los usuarios no verificados con paginación
     * @param pageable Información de paginación
     * @return Página de usuarios no verificados
     */
    Page<User> findUnverifiedUsers(Pageable pageable);

    // ===== MÉTODOS DE CONSULTA DE ROLES (SOLO LECTURA) =====

    /**
     * Encuentra usuarios por rol específico
     * @param roleName Nombre del rol (ej: "ROLE_ADMIN", "ROLE_USER")
     * @param pageable Información de paginación
     * @return Página de usuarios con el rol especificado
     */
    Page<User> findUsersByRole(String roleName, Pageable pageable);

    /**
     * Encuentra todos los usuarios administradores
     * @param pageable Información de paginación
     * @return Página de usuarios con rol ROLE_ADMIN
     */
    Page<User> findAdminUsers(Pageable pageable);

    /**
     * Encuentra todos los usuarios regulares (no admin)
     * @param pageable Información de paginación
     * @return Página de usuarios con rol ROLE_USER
     */
    Page<User> findRegularUsers(Pageable pageable);

    /**
     * Cuenta usuarios por rol
     * @param roleName Nombre del rol a contar
     * @return Número de usuarios con ese rol
     */
    long countUsersByRole(String roleName);

    /**
     * Verifica si un usuario tiene un rol específico
     * @param userId ID del usuario
     * @param roleName Nombre del rol a verificar
     * @return true si el usuario tiene ese rol
     */
    boolean userHasRole(Long userId, String roleName);

    /**
     * Obtiene el rol del usuario (único)
     * @param userId ID del usuario
     * @return Rol del usuario
     */
    Role getUserRole(Long userId);

    /**
     * Obtiene el nombre del rol del usuario
     * @param userId ID del usuario
     * @return Nombre del rol del usuario
     */
    String getUserRoleName(Long userId);

    // ===== MÉTODOS DE USUARIOS POR SUSCRIPCIÓN Y TIPO =====

    /**
     * Encuentra todos los usuarios PRO (que son PRO_SELLER)
     * @param pageable Información de paginación
     * @return Página de usuarios con suscripción PRO
     */
    Page<User> findProUsers(Pageable pageable);

    /**
     * Encuentra todos los usuarios FREE (que son INDIVIDUAL)
     * @param pageable Información de paginación
     * @return Página de usuarios con suscripción FREE
     */
    Page<User> findFreeUsers(Pageable pageable);

    /**
     * Encuentra todos los vendedores profesionales (PRO_SELLER + PRO)
     * @param pageable Información de paginación
     * @return Página de vendedores profesionales
     */
    Page<User> findProSellers(Pageable pageable);

    /**
     * Encuentra todos los usuarios individuales (INDIVIDUAL + FREE)
     * @param pageable Información de paginación
     * @return Página de usuarios individuales
     */
    Page<User> findIndividualUsers(Pageable pageable);

    // ===== MÉTODOS COMBINADOS: ROLES + TIERS =====

    /**
     * Encuentra administradores que también son PRO_SELLER
     * @param pageable Información de paginación
     * @return Página de admins que son vendedores profesionales
     */
    Page<User> findAdminProSellers(Pageable pageable);

    /**
     * Encuentra usuarios regulares que son PRO_SELLER
     * @param pageable Información de paginación
     * @return Página de usuarios regulares que son vendedores profesionales
     */
    Page<User> findRegularProSellers(Pageable pageable);

    /**
     * Encuentra administradores que son usuarios básicos (FREE+INDIVIDUAL)
     * @param pageable Información de paginación
     * @return Página de admins que son usuarios básicos
     */
    Page<User> findAdminBasicUsers(Pageable pageable);

    // ===== MÉTODOS DE CONVERSIÓN Y DTO =====

    /**
     * Convierte un usuario a DTO
     * @param user Usuario a convertir
     * @return DTO del usuario
     */
    UserDto convertUserToDto(User user);

    /**
     * Obtiene un usuario como DTO por su ID
     * @param userId ID del usuario
     * @return DTO del usuario
     */
    UserDto getUserDto(Long userId);

    /**
     * Obtiene el usuario autenticado actualmente
     * @return Usuario autenticado
     * @throws RuntimeException si no hay usuario autenticado
     */
    User getAuthenticatedUser();

    // ===== MÉTODOS DE CREACIÓN CON ROL INMUTABLE =====

    User createUser(CreateUserRequest request);

    @PreAuthorize("hasRole('ADMIN')")
    User createAdminUser(CreateUserRequest request);

    @PreAuthorize("hasRole('ADMIN')")
    User createVerifiedUser(CreateUserRequest request);

    User createUserWithRole(CreateUserRequest request, String roleName);

    // ===== MÉTODOS DE ACTUALIZACIÓN (SIN MODIFICACIÓN DE ROLES) =====

    User updateUser(UserUpdateRequest request, Long userId);

    User updateContactInfo(Long userId, UpdateContactInfoRequest request);

    User updateBusinessInfo(Long userId, UpdateBusinessInfoRequest request);

    @PreAuthorize("hasRole('ADMIN')")
    void deleteUser(Long userId);

    // ===== MÉTODO ÚNICO DE UPGRADE CORREGIDO =====

    User upgradeToProSeller(Long userId, UpgradeToProSellerRequest request);

    // ===== MÉTODOS DE VALIDACIÓN Y SEGURIDAD =====

    /**
     * Valida que un usuario puede ser promovido a vendedor profesional
     * @param userId ID del usuario
     * @return true si puede ser upgradeado
     */
    boolean canUpgradeToProSeller(Long userId);

    /**
     * Verifica si un usuario puede acceder a funcionalidades de administrador
     * @param userId ID del usuario
     * @return true si es administrador
     */
    boolean canAccessAdminFeatures(Long userId);

    /**
     * Verifica si un usuario puede ver información de otros usuarios
     * @param currentUserId ID del usuario actual
     * @param targetUserId ID del usuario objetivo
     * @return true si puede ver los detalles
     */
    boolean canViewUserDetails(Long currentUserId, Long targetUserId);

    // ===== MÉTODOS DE ESTADÍSTICAS Y REPORTES =====

    /**
     * Obtiene estadísticas de usuarios por rol
     * @return Mapa con el conteo de usuarios por rol
     */
    Map<String, Long> getUserStatsByRole();

    /**
     * Obtiene estadísticas de usuarios por tipo y suscripción
     * @return Mapa con el conteo de usuarios por tipo y suscripción
     */
    Map<String, Long> getUserStatsByTypeAndSubscription();

    /**
     * Cuenta el total de usuarios activos
     * @return Número de usuarios activos
     */
    long countActiveUsers();

    /**
     * Cuenta el total de usuarios verificados
     * @return Número de usuarios verificados
     */
    long countVerifiedUsers();

    /**
     * Cuenta el total de usuarios administradores
     * @return Número de usuarios con rol ROLE_ADMIN
     */
    long countAdminUsers();

    /**
     * Cuenta el total de usuarios regulares
     * @return Número de usuarios con rol ROLE_USER
     */
    long countRegularUsers();

    // ===== MÉTODOS DE INFORMACIÓN DEL SISTEMA =====

    /**
     * Obtiene información sobre la política de roles inmutables
     * @return Texto explicativo sobre por qué los roles son inmutables
     */
    String getRoleImmutabilityInfo();

    /**
     * Obtiene los roles disponibles en el sistema
     * @return Lista de todos los roles disponibles
     */
    List<Role> getAvailableRoles();

    /**
     * Verifica si un rol existe en el sistema
     * @param roleName Nombre del rol a verificar
     * @return true si el rol existe
     */
    boolean roleExists(String roleName);

    // ===== MÉTODOS ADICIONALES PARA COMPATIBILIDAD =====

    /**
     * Obtiene información de suscripción del usuario
     * @param userId ID del usuario
     * @return Información detallada de la suscripción
     */
    default Object getSubscriptionInfo(Long userId) {
        User user = getUserById(userId);
        return new Object() {
            public String getSubscriptionType() { return user.getSubscriptionType().toString(); }
            public String getUserType() { return user.getUserType().toString(); }
            public java.time.LocalDateTime getUpgradedAt() { return user.getUpgradedToProAt(); }
            public boolean isProSeller() { return user.isProSeller(); }
        };
    }

    /**
     * Verifica si un usuario puede ser promovido a admin
     * @param userId ID del usuario
     * @return false (los roles son inmutables)
     */
    default boolean canPromoteToAdmin(Long userId) {
        return false; // Los roles son inmutables
    }

    /**
     * Verifica si se pueden revocar privilegios de admin
     * @param userId ID del usuario
     * @return false (los roles son inmutables)
     */
    default boolean canRevokeAdminPrivileges(Long userId) {
        return false; // Los roles son inmutables
    }

    /**
     * Obtiene estadísticas completas de usuarios
     * @return Estadísticas de usuarios del sistema
     */
    default Object getUserStatistics() {
        Map<String, Long> roleStats = getUserStatsByRole();
        Map<String, Long> tierStats = getUserStatsByTypeAndSubscription();

        return new Object() {
            public long totalUsers() { return countActiveUsers() + countRegularUsers(); }
            public long activeUsers() { return countActiveUsers(); }
            public long verifiedUsers() { return countVerifiedUsers(); }
            public long adminUsers() { return countAdminUsers(); }
            public long regularUsers() { return countRegularUsers(); }
            public long proSellers() { return tierStats.getOrDefault("PRO_SELLER_PRO", 0L); }
            public long individualUsers() { return tierStats.getOrDefault("INDIVIDUAL_FREE", 0L); }
            public long freeUsers() { return tierStats.getOrDefault("INDIVIDUAL_FREE", 0L); }
            public long proUsers() { return tierStats.getOrDefault("PRO_SELLER_PRO", 0L); }
        };
    }

}