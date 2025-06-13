package com.figrclub.figrclubdb.service.user;

import com.figrclub.figrclubdb.domain.model.Role;
import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
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
import java.util.Set;

/**
 * Interface del servicio de usuarios CORREGIDA con funcionalidades completas:
 * - Lógica consistente de tiers: FREE+INDIVIDUAL y PRO+PRO_SELLER
 * - Funcionalidad completa de roles (USER, ADMIN)
 * - Métodos para gestión de roles y permisos
 */
public interface IUserService {

    // ===== MÉTODOS DE BÚSQUEDA BÁSICA =====

    /**
     * Encuentra un usuario por su ID
     */
    User getUserById(Long userId);

    /**
     * Encuentra un usuario por su email
     */
    Optional<User> findByEmail(String email);

    /**
     * Verifica si existe un usuario con el email dado
     */
    boolean existsByEmail(String email);

    /**
     * Busca usuarios por nombre o email
     */
    Page<User> searchUsers(String searchTerm, Pageable pageable);

    // ===== MÉTODOS DE LISTADO CON PAGINACIÓN =====

    /**
     * Encuentra todos los usuarios con paginación
     */
    Page<User> findAllUsers(Pageable pageable);

    /**
     * Encuentra todos los usuarios activos (verificados) con paginación
     */
    Page<User> findActiveUsers(Pageable pageable);

    /**
     * Encuentra todos los usuarios verificados con paginación
     */
    Page<User> findVerifiedUsers(Pageable pageable);

    /**
     * Encuentra todos los usuarios no verificados con paginación
     */
    Page<User> findUnverifiedUsers(Pageable pageable);

    // ===== MÉTODOS DE ROLES AÑADIDOS/CORREGIDOS =====

    /**
     * Encuentra usuarios por rol específico
     */
    Page<User> findUsersByRole(String roleName, Pageable pageable);

    /**
     * Encuentra todos los usuarios administradores
     */
    Page<User> findAdminUsers(Pageable pageable);

    /**
     * Encuentra todos los usuarios regulares (no admin)
     */
    Page<User> findRegularUsers(Pageable pageable);

    /**
     * Cuenta usuarios por rol
     */
    long countUsersByRole(String roleName);

    /**
     * Verifica si un usuario tiene un rol específico
     */
    boolean userHasRole(Long userId, String roleName);

    /**
     * Obtiene todos los roles de un usuario
     */
    Set<Role> getUserRoles(Long userId);

    /**
     * Asigna un rol a un usuario
     */
    User assignRoleToUser(Long userId, String roleName);

    /**
     * Remueve un rol de un usuario
     */
    User removeRoleFromUser(Long userId, String roleName);

    /**
     * Actualiza los roles de un usuario (reemplaza todos)
     */
    User updateUserRoles(Long userId, Set<String> roleNames);

    // ===== MÉTODOS CORREGIDOS PARA SUSCRIPCIONES =====

    /**
     * Encuentra todos los usuarios PRO (que son PRO_SELLER)
     * En la lógica corregida: PRO = PRO_SELLER
     */
    Page<User> findProUsers(Pageable pageable);

    /**
     * Encuentra todos los usuarios FREE (que son INDIVIDUAL)
     * En la lógica corregida: FREE = INDIVIDUAL
     */
    Page<User> findFreeUsers(Pageable pageable);

    /**
     * Encuentra todos los vendedores profesionales (PRO_SELLER + PRO)
     */
    Page<User> findProSellers(Pageable pageable);

    /**
     * Encuentra todos los usuarios individuales (INDIVIDUAL + FREE)
     */
    Page<User> findIndividualUsers(Pageable pageable);

    // ===== MÉTODOS COMBINADOS: ROLES + TIERS =====

    /**
     * Encuentra administradores que también son PRO_SELLER
     */
    Page<User> findAdminProSellers(Pageable pageable);

    /**
     * Encuentra usuarios regulares que son PRO_SELLER
     */
    Page<User> findRegularProSellers(Pageable pageable);

    /**
     * Encuentra administradores que son usuarios básicos (FREE+INDIVIDUAL)
     */
    Page<User> findAdminBasicUsers(Pageable pageable);

    // ===== MÉTODOS DE CONVERSIÓN Y DTO =====

    /**
     * Convierte un usuario a DTO
     */
    UserDto convertUserToDto(User user);

    /**
     * Obtiene un usuario como DTO por su ID
     */
    UserDto getUserDto(Long userId);

    /**
     * Obtiene el usuario autenticado actualmente
     */
    User getAuthenticatedUser();

    // ===== MÉTODOS DE CREACIÓN =====

    /**
     * Crea un nuevo usuario con rol USER (FREE + INDIVIDUAL por defecto)
     */
    User createUser(CreateUserRequest request);

    /**
     * Crea un nuevo usuario con rol ADMIN (FREE + INDIVIDUAL por defecto)
     */
    User createAdminUser(CreateUserRequest request);

    /**
     * Crea un nuevo usuario pre-verificado (solo uso administrativo)
     */
    User createVerifiedUser(CreateUserRequest request);

    /**
     * Crea un usuario con roles específicos
     */
    User createUserWithRoles(CreateUserRequest request, Set<String> roleNames);

    // ===== MÉTODOS DE ACTUALIZACIÓN =====

    /**
     * Actualiza un usuario existente
     */
    User updateUser(UserUpdateRequest request, Long userId);

    /**
     * Elimina un usuario por su ID
     */
    void deleteUser(Long userId);

    // ===== MÉTODO ÚNICO DE UPGRADE CORREGIDO =====

    /**
     * ÚNICO UPGRADE PERMITIDO: FREE+INDIVIDUAL → PRO+PRO_SELLER
     * Actualiza un usuario básico a vendedor profesional con suscripción PRO
     */
    User upgradeToProSeller(Long userId, UpgradeToProSellerRequest request);

    /**
     * Actualiza información de contacto adicional
     */
    User updateContactInfo(Long userId, UpdateContactInfoRequest request);

    /**
     * Actualiza información de negocio (solo para PRO_SELLER)
     */
    User updateBusinessInfo(Long userId, UpdateBusinessInfoRequest request);

    // ===== MÉTODOS DE VERIFICACIÓN DE EMAIL =====

    /**
     * Verifica el email de un usuario
     */
    User verifyUserEmail(User user);

    /**
     * Verifica si un email está verificado
     */
    boolean isEmailVerified(String email);

    // ===== MÉTODOS DE ACTIVACIÓN/DESACTIVACIÓN =====

    /**
     * Deshabilita un usuario (uso administrativo)
     */
    User disableUser(Long userId);

    /**
     * Habilita un usuario manualmente (uso administrativo)
     */
    User enableUser(Long userId);

    /**
     * Desactiva un usuario (alias para disableUser para compatibilidad)
     */
    User deactivateUser(Long userId);

    /**
     * Activa un usuario (alias para enableUser para compatibilidad)
     */
    User activateUser(Long userId);

    // ===== MÉTODOS DE VERIFICACIÓN CORREGIDOS =====

    /**
     * Verifica si un usuario puede actualizar a vendedor profesional
     * Solo FREE+INDIVIDUAL pueden upgradear a PRO+PRO_SELLER
     */
    boolean canUpgradeToProSeller(Long userId);

    /**
     * @deprecated Usar canUpgradeToProSeller() en su lugar
     * Solo existe para compatibilidad con código existente
     */
    @Deprecated
    boolean canUpgradeSubscription(Long userId);

    /**
     * Obtiene información de suscripción de un usuario
     */
    UserService.UserSubscriptionInfo getSubscriptionInfo(Long userId);

    // ===== MÉTODOS DE ESTADÍSTICAS ACTUALIZADOS =====

    /**
     * Obtiene estadísticas de usuarios corregidas (incluye roles)
     */
    UserService.UserStats getUserStats();

    /**
     * Obtiene estadísticas de roles
     */
    UserService.RoleStats getRoleStats();

    /**
     * Obtiene distribución completa: roles + tiers
     */
    UserService.CompleteDistribution getCompleteDistribution();

    // ===== MÉTODOS DE VALIDACIÓN DE CONFIGURACIONES =====

    /**
     * Verifica si un usuario tiene una configuración válida
     */
    boolean hasValidConfiguration(Long userId);

    /**
     * Encuentra usuarios con configuraciones inválidas
     */
    List<User> findUsersWithInvalidConfigurations();

    /**
     * Cuenta usuarios con configuraciones inválidas
     */
    long countUsersWithInvalidConfigurations();

    // ===== MÉTODOS ADMINISTRATIVOS DE CORRECCIÓN =====

    /**
     * Corrige automáticamente configuraciones inválidas (solo admin)
     * @return número de usuarios corregidos
     */
    @PreAuthorize("hasRole('ADMIN')")
    int fixInvalidUserConfigurations();

    // ===== MÉTODOS DE REPORTES =====

    /**
     * Obtiene la distribución de configuraciones de usuarios
     */
    Map<String, Long> getConfigurationDistribution();

    /**
     * Obtiene un reporte completo de salud del sistema
     */
    UserService.SystemHealthReport getSystemHealthReport();

    // ===== MÉTODOS DE GESTIÓN DE ROLES AVANZADOS =====

    /**
     * Promociona un usuario regular a administrador
     */
    @PreAuthorize("hasRole('ADMIN')")
    User promoteToAdmin(Long userId);

    /**
     * Revoca privilegios de administrador de un usuario
     */
    @PreAuthorize("hasRole('ADMIN')")
    User revokeAdminPrivileges(Long userId);

    /**
     * Verifica si un usuario puede ser promovido a admin
     */
    boolean canPromoteToAdmin(Long userId);

    /**
     * Verifica si se pueden revocar privilegios de admin a un usuario
     * (no se puede si es el último admin del sistema)
     */
    boolean canRevokeAdminPrivileges(Long userId);

    /**
     * Obtiene el número total de administradores en el sistema
     */
    long getAdminCount();
}
