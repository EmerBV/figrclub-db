package com.figrclub.figrclubdb.service.user;

import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
import com.figrclub.figrclubdb.request.CreateUserRequest;
import com.figrclub.figrclubdb.request.UpdateContactInfoRequest;
import com.figrclub.figrclubdb.request.UpdateBusinessInfoRequest;
import com.figrclub.figrclubdb.request.UpgradeToProSellerRequest;
import com.figrclub.figrclubdb.request.UpgradeSubscriptionRequest;
import com.figrclub.figrclubdb.request.UserUpdateRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Optional;

/**
 * Interface del servicio de usuarios con soporte completo para verificación de email,
 * gestión de usuarios y sistema de suscripciones/tipos de usuario
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

    // ===== MÉTODOS PARA SUSCRIPCIONES Y TIPOS DE USUARIO =====

    /**
     * Encuentra todos los usuarios con suscripción PRO
     */
    Page<User> findProUsers(Pageable pageable);

    /**
     * Encuentra todos los usuarios con suscripción FREE
     */
    Page<User> findFreeUsers(Pageable pageable);

    /**
     * Encuentra todos los vendedores profesionales
     */
    Page<User> findProSellers(Pageable pageable);

    /**
     * Encuentra todos los usuarios individuales
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
     * Crea un nuevo usuario con rol USER (deshabilitado por defecto)
     */
    User createUser(CreateUserRequest request);

    /**
     * Crea un nuevo usuario con rol ADMIN (deshabilitado por defecto)
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

    // ===== MÉTODOS DE UPGRADE DE USUARIOS =====

    /**
     * Actualiza un usuario a vendedor profesional con suscripción PRO
     */
    User upgradeToProSeller(Long userId, UpgradeToProSellerRequest request);

    /**
     * Actualiza solo la suscripción a PRO manteniendo el tipo de usuario
     */
    User upgradeSubscriptionToPro(Long userId, UpgradeSubscriptionRequest request);

    /**
     * Actualiza información de contacto adicional
     */
    User updateContactInfo(Long userId, UpdateContactInfoRequest request);

    /**
     * Actualiza información de negocio (solo para vendedores profesionales)
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

    // ===== MÉTODOS DE VERIFICACIÓN ADICIONALES =====

    /**
     * Verifica si un usuario puede actualizar a vendedor profesional
     */
    boolean canUpgradeToProSeller(Long userId);

    /**
     * Verifica si un usuario puede actualizar su suscripción
     */
    boolean canUpgradeSubscription(Long userId);

    /**
     * Obtiene información de suscripción de un usuario
     */
    UserService.UserSubscriptionInfo getSubscriptionInfo(Long userId);

    // ===== MÉTODOS DE ESTADÍSTICAS =====

    /**
     * Obtiene estadísticas de usuarios
     */
    UserService.UserStats getUserStats();
}
