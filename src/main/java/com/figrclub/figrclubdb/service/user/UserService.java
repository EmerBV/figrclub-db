package com.figrclub.figrclubdb.service.user;

import com.figrclub.figrclubdb.domain.model.Role;
import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.enums.UserType;
import com.figrclub.figrclubdb.exceptions.AlreadyExistsException;
import com.figrclub.figrclubdb.exceptions.ResourceNotFoundException;
import com.figrclub.figrclubdb.repository.RoleRepository;
import com.figrclub.figrclubdb.repository.UserRepository;
import com.figrclub.figrclubdb.request.CreateUserRequest;
import com.figrclub.figrclubdb.request.UpdateContactInfoRequest;
import com.figrclub.figrclubdb.request.UpdateBusinessInfoRequest;
import com.figrclub.figrclubdb.request.UpgradeToProSellerRequest;
import com.figrclub.figrclubdb.request.UpgradeSubscriptionRequest;
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

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Optional;
import java.util.Set;

/**
 * Servicio de usuarios actualizado con soporte para verificación de email
 * y sistema de suscripciones/tipos de usuario
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
    public boolean existsByEmail(String email) {
        log.debug("Checking if user exists by email: {}", email);
        return userRepository.existsByEmail(email);
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

    // ===== MÉTODOS PARA SUSCRIPCIONES Y TIPOS DE USUARIO =====

    @Override
    @Transactional(readOnly = true)
    public Page<User> findProUsers(Pageable pageable) {
        log.debug("Finding PRO users with pagination: {}", pageable);
        return userRepository.findBySubscriptionType(SubscriptionType.PRO, pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findFreeUsers(Pageable pageable) {
        log.debug("Finding FREE users with pagination: {}", pageable);
        return userRepository.findBySubscriptionType(SubscriptionType.FREE, pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findProSellers(Pageable pageable) {
        log.debug("Finding Pro Seller users with pagination: {}", pageable);
        return userRepository.findByUserType(UserType.PRO_SELLER, pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findIndividualUsers(Pageable pageable) {
        log.debug("Finding Individual users with pagination: {}", pageable);
        return userRepository.findByUserType(UserType.INDIVIDUAL, pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public UserDto convertUserToDto(User user) {
        log.debug("Converting user to DTO: {}", user.getId());

        // Usar ModelMapper para el mapeo básico
        UserDto userDto = modelMapper.map(user, UserDto.class);

        // Mapear campos adicionales manualmente
        userDto.setFullName(user.getFullName());
        userDto.setDisplayName(user.getDisplayName());
        userDto.setAdmin(user.isAdmin());

        // Mapear campos de estado correctamente
        userDto.setEnabled(user.isEnabled());
        userDto.setAccountNonExpired(user.isAccountNonExpired());
        userDto.setAccountNonLocked(user.isAccountNonLocked());
        userDto.setCredentialsNonExpired(user.isCredentialsNonExpired());

        // Mapear fecha de verificación de email
        userDto.setEmailVerifiedAt(user.getEmailVerifiedAt());

        // Mapear campos de suscripción y tipo de usuario
        userDto.setUserType(user.getUserType());
        userDto.setSubscriptionType(user.getSubscriptionType());
        userDto.setUpgradedToProAt(user.getUpgradedToProAt());

        // Mapear campos de negocio (solo si es vendedor profesional)
        if (user.isProSeller()) {
            userDto.setBusinessName(user.getBusinessName());
            userDto.setBusinessDescription(user.getBusinessDescription());
            userDto.setBusinessLogoUrl(user.getBusinessLogoUrl());
            userDto.setFiscalAddress(user.getFiscalAddress());
            userDto.setTaxId(user.getTaxId());
            userDto.setPaymentMethod(user.getPaymentMethod());
        }

        // Mapear campos de contacto
        userDto.setPhone(user.getPhone());
        userDto.setCountry(user.getCountry());
        userDto.setCity(user.getCity());
        userDto.setBirthDate(user.getBirthDate());

        // Mapear roles como lista de strings
        if (user.getRoles() != null && !user.getRoles().isEmpty()) {
            userDto.setRoles(user.getRoles().stream()
                    .map(Role::getName)
                    .toList());
        }

        return userDto;
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
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new ResourceNotFoundException("Authenticated user not found: " + email);
        }
        return user;
    }

    /**
     * Crea un usuario con rol específico (MANTIENE LA FUNCIONALIDAD ORIGINAL)
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
                .isEnabled(false) // Usuario deshabilitado hasta verificar email
                .isAccountNonExpired(true)
                .isAccountNonLocked(true)
                .isCredentialsNonExpired(true)
                // NUEVOS CAMPOS CON VALORES POR DEFECTO
                .userType(UserType.INDIVIDUAL)
                .subscriptionType(SubscriptionType.FREE)
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

    // ===== MÉTODOS PARA UPGRADE DE USUARIOS =====

    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User upgradeToProSeller(Long userId, UpgradeToProSellerRequest request) {
        log.info("Upgrading user {} to Pro Seller", userId);

        User user = getUserById(userId);

        if (user.isProSeller()) {
            throw new IllegalStateException("User is already a Pro Seller");
        }

        user.upgradeToProSeller(
                request.getBusinessName(),
                request.getBusinessDescription(),
                request.getFiscalAddress(),
                request.getTaxId(),
                request.getPaymentMethod()
        );

        if (request.getBusinessLogoUrl() != null) {
            user.setBusinessLogoUrl(request.getBusinessLogoUrl());
        }

        User savedUser = userRepository.save(user);
        log.info("User {} successfully upgraded to Pro Seller", userId);

        return savedUser;
    }

    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User upgradeSubscriptionToPro(Long userId, UpgradeSubscriptionRequest request) {
        log.info("Upgrading subscription to PRO for user {}", userId);

        User user = getUserById(userId);

        if (user.isPro()) {
            throw new IllegalStateException("User already has PRO subscription");
        }

        user.upgradeSubscriptionToPro(request.getPaymentMethod());

        User savedUser = userRepository.save(user);
        log.info("User {} subscription upgraded to PRO", userId);

        return savedUser;
    }

    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User updateContactInfo(Long userId, UpdateContactInfoRequest request) {
        log.info("Updating contact info for user {}", userId);

        User user = getUserById(userId);

        LocalDate birthDate = null;
        if (request.getBirthDate() != null && !request.getBirthDate().trim().isEmpty()) {
            try {
                birthDate = LocalDate.parse(request.getBirthDate(), DateTimeFormatter.ISO_LOCAL_DATE);
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid birth date format: " + request.getBirthDate());
            }
        }

        user.updateContactInfo(
                request.getPhone(),
                request.getCountry(),
                request.getCity(),
                birthDate
        );

        User savedUser = userRepository.save(user);
        log.info("Contact info updated for user {}", userId);

        return savedUser;
    }

    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User updateBusinessInfo(Long userId, UpdateBusinessInfoRequest request) {
        log.info("Updating business info for user {}", userId);

        User user = getUserById(userId);

        if (!user.isProSeller()) {
            throw new IllegalStateException("User must be a Pro Seller to update business information");
        }

        user.updateBusinessInfo(
                request.getBusinessName(),
                request.getBusinessDescription(),
                request.getBusinessLogoUrl()
        );

        User savedUser = userRepository.save(user);
        log.info("Business info updated for user {}", userId);

        return savedUser;
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
     * Desactiva un usuario (alias para disableUser para compatibilidad)
     */
    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User deactivateUser(Long userId) {
        log.info("Deactivating user with ID: {}", userId);
        return disableUser(userId);
    }

    /**
     * Activa un usuario (alias para enableUser para compatibilidad)
     */
    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User activateUser(Long userId) {
        log.info("Activating user with ID: {}", userId);
        return enableUser(userId);
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
     * Obtiene estadísticas de usuarios ACTUALIZADAS
     */
    @Override
    @Transactional(readOnly = true)
    public UserStats getUserStats() {
        long totalUsers = userRepository.count();
        long verifiedUsers = userRepository.countByIsEnabledTrue();
        long unverifiedUsers = totalUsers - verifiedUsers;

        // NUEVAS ESTADÍSTICAS
        long proUsers = userRepository.countBySubscriptionType(SubscriptionType.PRO);
        long freeUsers = userRepository.countBySubscriptionType(SubscriptionType.FREE);
        long proSellers = userRepository.countByUserType(UserType.PRO_SELLER);
        long individualUsers = userRepository.countByUserType(UserType.INDIVIDUAL);

        return new UserStats(
                totalUsers,
                verifiedUsers,
                unverifiedUsers,
                proUsers,
                freeUsers,
                proSellers,
                individualUsers
        );
    }

    /**
     * Record para estadísticas de usuarios ACTUALIZADO
     */
    public record UserStats(
            long totalUsers,
            long verifiedUsers,
            long unverifiedUsers,
            long proUsers,
            long freeUsers,
            long proSellers,
            long individualUsers
    ) {}

    /**
     * Busca usuarios por nombre o email
     */
    @Override
    @Transactional(readOnly = true)
    public Page<User> searchUsers(String searchTerm, Pageable pageable) {
        log.debug("Searching users with term: {}", searchTerm);

        if (searchTerm == null || searchTerm.trim().isEmpty()) {
            throw new IllegalArgumentException("Search term cannot be empty");
        }

        String cleanSearchTerm = searchTerm.trim();
        return userRepository.findByNameContainingIgnoreCase(cleanSearchTerm, pageable);
    }

    // ===== MÉTODOS DE VERIFICACIÓN ADICIONALES =====

    @Override
    @Transactional(readOnly = true)
    public boolean canUpgradeToProSeller(Long userId) {
        try {
            User user = getUserById(userId);
            return !user.isProSeller() && user.isEmailVerified();
        } catch (ResourceNotFoundException e) {
            return false;
        }
    }

    @Override
    @Transactional(readOnly = true)
    public boolean canUpgradeSubscription(Long userId) {
        try {
            User user = getUserById(userId);
            return !user.isPro() && user.isEmailVerified();
        } catch (ResourceNotFoundException e) {
            return false;
        }
    }

    @Override
    @Transactional(readOnly = true)
    public UserSubscriptionInfo getSubscriptionInfo(Long userId) {
        User user = getUserById(userId);

        return new UserSubscriptionInfo(
                user.getSubscriptionType(),
                user.getUserType(),
                user.isPro(),
                user.isProSeller(),
                user.canAccessProFeatures(),
                user.getUpgradedToProAt(),
                user.getPaymentMethod()
        );
    }

    /**
     * Record para información de suscripción
     */
    public record UserSubscriptionInfo(
            SubscriptionType subscriptionType,
            UserType userType,
            boolean isPro,
            boolean isProSeller,
            boolean canAccessProFeatures,
            LocalDateTime upgradedToProAt,
            String paymentMethod
    ) {}
}
