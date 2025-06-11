package com.figrclub.figrclubdb.service.user;

import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
import com.figrclub.figrclubdb.request.CreateUserRequest;
import com.figrclub.figrclubdb.request.UserUpdateRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Optional;

/**
 * Interface del servicio de usuarios con soporte para verificación de email
 */
public interface IUserService {

    /**
     * Encuentra un usuario por su ID
     * @param userId ID del usuario
     * @return Usuario encontrado
     * //@throws ResourceNotFoundException si no se encuentra el usuario
     */
    User getUserById(Long userId);

    /**
     * Encuentra un usuario por su email
     * @param email Email del usuario
     * @return Optional con el usuario si existe
     */
    Optional<User> findByEmail(String email);

    /**
     * Encuentra todos los usuarios con paginación
     * @param pageable Información de paginación
     * @return Página de usuarios
     */
    Page<User> findAllUsers(Pageable pageable);

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

    /**
     * Convierte un usuario a DTO
     * @param user Usuario a convertir
     * @return UserDto
     */
    UserDto convertUserToDto(User user);

    /**
     * Obtiene un usuario como DTO por su ID
     * @param userId ID del usuario
     * @return UserDto
     */
    UserDto getUserDto(Long userId);

    /**
     * Obtiene el usuario autenticado actualmente
     * @return Usuario autenticado
     */
    User getAuthenticatedUser();

    /**
     * Crea un nuevo usuario con rol USER (deshabilitado por defecto)
     * @param request Datos del usuario a crear
     * @return Usuario creado
     * //@throws AlreadyExistsException si el email ya existe
     */
    User createUser(CreateUserRequest request);

    /**
     * Crea un nuevo usuario con rol ADMIN (deshabilitado por defecto)
     * @param request Datos del usuario a crear
     * @return Usuario creado
     * //@throws AlreadyExistsException si el email ya existe
     */
    User createAdminUser(CreateUserRequest request);

    /**
     * Crea un nuevo usuario pre-verificado (solo uso administrativo)
     * @param request Datos del usuario a crear
     * @return Usuario creado y verificado
     * //@throws AlreadyExistsException si el email ya existe
     */
    User createVerifiedUser(CreateUserRequest request);

    /**
     * Actualiza un usuario existente
     * @param request Datos a actualizar
     * @param userId ID del usuario
     * @return Usuario actualizado
     * //@throws ResourceNotFoundException si no se encuentra el usuario
     */
    User updateUser(UserUpdateRequest request, Long userId);

    /**
     * Elimina un usuario por su ID
     * @param userId ID del usuario a eliminar
     * //@throws ResourceNotFoundException si no se encuentra el usuario
     */
    void deleteUser(Long userId);

    /**
     * Verifica el email de un usuario
     * @param user Usuario a verificar
     * @return Usuario con email verificado
     */
    User verifyUserEmail(User user);

    /**
     * Deshabilita un usuario (uso administrativo)
     * @param userId ID del usuario
     * @return Usuario deshabilitado
     */
    User disableUser(Long userId);

    /**
     * Habilita un usuario manualmente (uso administrativo)
     * @param userId ID del usuario
     * @return Usuario habilitado
     */
    User enableUser(Long userId);

    /**
     * Verifica si un email está verificado
     * @param email Email a verificar
     * @return true si está verificado, false si no
     */
    boolean isEmailVerified(String email);

    /**
     * Obtiene estadísticas de usuarios
     * @return Estadísticas de usuarios
     */
    UserService.UserStats getUserStats();
}
