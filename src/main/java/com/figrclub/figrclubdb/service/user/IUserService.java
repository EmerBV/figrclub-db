package com.figrclub.figrclubdb.service.user;

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

/**
 * Interface del servicio de usuarios CORREGIDA con lógica consistente:
 * - Solo permite FREE + INDIVIDUAL (usuarios básicos)
 * - Solo permite PRO + PRO_SELLER (vendedores profesionales)
 * - Elimina métodos que permitían combinaciones inconsistentes
 */
public interface IUserService {

    // ===== MÉTODOS DE BÚSQUEDA =====

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

    // ===== MÉTODOS DE ESTADÍSTICAS =====

    /**
     * Obtiene estadísticas de usuarios corregidas
     */
    UserService.UserStats getUserStats();

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
}
