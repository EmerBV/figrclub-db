package com.figrclub.figrclubdb.service.user;

import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
import com.figrclub.figrclubdb.request.CreateUserRequest;
import com.figrclub.figrclubdb.request.UserUpdateRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Optional;

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
     * Encuentra todos los usuarios activos con paginación
     * @param pageable Información de paginación
     * @return Página de usuarios activos
     */
    Page<User> findActiveUsers(Pageable pageable);

    /**
     * Crea un nuevo usuario con rol USER
     * @param request Datos del usuario a crear
     * @return Usuario creado
     * //@throws AlreadyExistsException si el email ya existe
     */
    User createUser(CreateUserRequest request);

    /**
     * Crea un nuevo usuario con rol ADMIN
     * @param request Datos del usuario a crear
     * @return Usuario creado
     * //@throws AlreadyExistsException si el email ya existe
     */
    User createAdminUser(CreateUserRequest request);

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
     * Desactiva un usuario (soft delete)
     * @param userId ID del usuario a desactivar
     * //@throws ResourceNotFoundException si no se encuentra el usuario
     */
    void deactivateUser(Long userId);

    /**
     * Activa un usuario previamente desactivado
     * @param userId ID del usuario a activar
     * //@throws ResourceNotFoundException si no se encuentra el usuario
     */
    void activateUser(Long userId);

    /**
     * Convierte un User entity a UserDto
     * @param user Usuario a convertir
     * @return DTO del usuario
     */
    UserDto convertUserToDto(User user);

    /**
     * Obtiene el usuario autenticado actualmente
     * @return Usuario autenticado
     * //@throws ResourceNotFoundException si no hay usuario autenticado
     */
    User getAuthenticatedUser();

    /**
     * Verifica si existe un usuario con el email dado
     * @param email Email a verificar
     * @return true si existe, false si no
     */
    boolean existsByEmail(String email);
}
