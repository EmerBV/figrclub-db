package com.figrclub.figrclubdb.service.user;

import com.figrclub.figrclubdb.domain.model.Role;
import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
import com.figrclub.figrclubdb.exceptions.AlreadyExistsException;
import com.figrclub.figrclubdb.exceptions.ResourceNotFoundException;
import com.figrclub.figrclubdb.repository.RoleRepository;
import com.figrclub.figrclubdb.repository.UserRepository;
import com.figrclub.figrclubdb.request.CreateUserRequest;
import com.figrclub.figrclubdb.request.UserUpdateRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.Set;

/**
 * Servicio de usuarios actualizado con soporte para verificación de email
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserService implements IUserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "#userId")
    public User getUserById(Long userId) {
        log.debug("Finding user by ID: {}", userId);
        return userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<User> findByEmail(String email) {
        log.debug("Finding user by email: {}", email);
        return userRepository.findOptionalByEmail(email);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findAllUsers(Pageable pageable) {
        log.debug("Finding all users with pagination: {}", pageable);
        return userRepository.findAll(pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findActiveUsers(Pageable pageable) {
        log.debug("Finding active users with pagination: {}", pageable);
        return userRepository.findByIsEnabledTrue(pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findVerifiedUsers(Pageable pageable) {
        log.debug("Finding verified users with pagination: {}", pageable);
        return userRepository.findByIsEnabledTrue(pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findUnverifiedUsers(Pageable pageable) {
        log.debug("Finding unverified users with pagination: {}", pageable);
        return userRepository.findByIsEnabledFalse(pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public UserDto convertUserToDto(User user) {
        log.debug("Converting user to DTO: {}", user.getId());
        return modelMapper.map(user, UserDto.class);
    }

    @Override
    @Transactional(readOnly = true)
    public UserDto getUserDto(Long userId) {
        User user = getUserById(userId);
        return convertUserToDto(user);
    }

    @Override
    @Transactional(readOnly = true)
    public User getAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new RuntimeException("No authenticated user found");
        }

        String email = authentication.getName();
        return userRepository.findByEmail(email);
    }

    /**
     * Crea un usuario con rol específico
     * IMPORTANTE: El usuario se crea DESHABILITADO por defecto para requerir verificación de email
     */
    private User createUserWithRole(CreateUserRequest request, String roleName) {
        log.info("Creating user with role {}: {}", roleName, request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Attempt to create user with existing email: {}", request.getEmail());
            throw new AlreadyExistsException("El usuario con email " + request.getEmail() + " ya existe");
        }

        Role userRole = roleRepository.findByName(roleName)
                .orElseThrow(() -> new ResourceNotFoundException("Rol no encontrado: " + roleName));

        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of(userRole))
                .isEnabled(false) // IMPORTANTE: Usuario deshabilitado hasta verificar email
                .isAccountNonExpired(true)
                .isAccountNonLocked(true)
                .isCredentialsNonExpired(true)
                .build();

        User savedUser = userRepository.save(user);
        log.info("User created successfully with ID: {} (email verification required)", savedUser.getId());

        return savedUser;
    }

    @Override
    @Transactional
    public User createUser(CreateUserRequest request) {
        return createUserWithRole(request, "ROLE_USER");
    }

    @Override
    @Transactional
    public User createAdminUser(CreateUserRequest request) {
        return createUserWithRole(request, "ROLE_ADMIN");
    }

    /**
     * Crea un usuario pre-verificado (solo para casos administrativos)
     */
    @Override
    @Transactional
    public User createVerifiedUser(CreateUserRequest request) {
        User user = createUserWithRole(request, "ROLE_USER");
        user.markEmailAsVerified();
        User savedUser = userRepository.save(user);
        log.info("Pre-verified user created with ID: {}", savedUser.getId());
        return savedUser;
    }

    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User updateUser(UserUpdateRequest request, Long userId) {
        log.info("Updating user with ID: {}", userId);

        return userRepository.findById(userId)
                .map(existingUser -> {
                    if (request.getFirstName() != null) {
                        existingUser.setFirstName(request.getFirstName());
                    }
                    if (request.getLastName() != null) {
                        existingUser.setLastName(request.getLastName());
                    }

                    User updatedUser = userRepository.save(existingUser);
                    log.info("User updated successfully: {}", updatedUser.getId());
                    return updatedUser;
                })
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));
    }

    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public void deleteUser(Long userId) {
        log.info("Deleting user with ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));

        userRepository.delete(user);
        log.info("User deleted successfully: {}", userId);
    }

    /**
     * Verifica el email de un usuario (llamado desde EmailVerificationService)
     */
    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#user.id")
    public User verifyUserEmail(User user) {
        log.info("Verifying email for user: {}", user.getEmail());

        if (!user.isEnabled()) {
            user.markEmailAsVerified();
            User savedUser = userRepository.save(user);
            log.info("Email verified successfully for user: {}", user.getEmail());
            return savedUser;
        } else {
            log.info("User email already verified: {}", user.getEmail());
            return user;
        }
    }

    /**
     * Deshabilita un usuario (uso administrativo)
     */
    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User disableUser(Long userId) {
        log.info("Disabling user with ID: {}", userId);

        User user = getUserById(userId);
        user.disable();
        User savedUser = userRepository.save(user);

        log.info("User disabled successfully: {}", userId);
        return savedUser;
    }

    /**
     * Habilita un usuario manualmente (uso administrativo)
     */
    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User enableUser(Long userId) {
        log.info("Enabling user with ID: {}", userId);

        User user = getUserById(userId);
        user.enable();
        User savedUser = userRepository.save(user);

        log.info("User enabled successfully: {}", userId);
        return savedUser;
    }

    /**
     * Verifica si un email está verificado
     */
    @Override
    @Transactional(readOnly = true)
    public boolean isEmailVerified(String email) {
        User user = userRepository.findByEmail(email);
        return user != null && user.isEmailVerified();
    }

    /**
     * Obtiene estadísticas de usuarios
     */
    @Override
    @Transactional(readOnly = true)
    public UserStats getUserStats() {
        long totalUsers = userRepository.count();
        long verifiedUsers = userRepository.countByIsEnabledTrue();
        long unverifiedUsers = totalUsers - verifiedUsers;

        return new UserStats(totalUsers, verifiedUsers, unverifiedUsers);
    }

    /**
     * Record para estadísticas de usuarios
     */
    public record UserStats(long totalUsers, long verifiedUsers, long unverifiedUsers) {}
}
