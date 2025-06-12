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
import com.figrclub.figrclubdb.request.UserUpdateRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Servicio de usuarios corregido con lógica consistente:
 * - Solo permite FREE + INDIVIDUAL
 * - Solo permite PRO + PRO_SELLER
 * - Elimina métodos que permitían combinaciones inconsistentes
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserService implements IUserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;

    // ===== MÉTODOS BÁSICOS DE BÚSQUEDA =====

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

    // ===== MÉTODOS CORREGIDOS PARA SUSCRIPCIONES =====

    @Override
    @Transactional(readOnly = true)
    public Page<User> findProUsers(Pageable pageable) {
        log.debug("Finding PRO users (PRO_SELLER) with pagination: {}", pageable);
        // PRO users son siempre PRO_SELLER según la lógica corregida
        return userRepository.findByUserType(UserType.PRO_SELLER, pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findFreeUsers(Pageable pageable) {
        log.debug("Finding FREE users (INDIVIDUAL) with pagination: {}", pageable);
        // FREE users son siempre INDIVIDUAL según la lógica corregida
        return userRepository.findByUserType(UserType.INDIVIDUAL, pageable);
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

    // ===== MÉTODOS DE CONVERSIÓN =====

    @Override
    @Transactional(readOnly = true)
    public UserDto convertUserToDto(User user) {
        log.debug("Converting user to DTO: {}", user.getId());

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

    // ===== MÉTODOS DE CREACIÓN =====

    /**
     * Crea un usuario con rol específico (SIEMPRE FREE + INDIVIDUAL)
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
                // LÓGICA CONSISTENTE: Todo usuario nuevo empieza como FREE + INDIVIDUAL
                .userType(UserType.INDIVIDUAL)
                .subscriptionType(SubscriptionType.FREE)
                .build();

        User savedUser = userRepository.save(user);
        log.info("User created successfully with ID: {} (FREE+INDIVIDUAL, email verification required)", savedUser.getId());

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

    @Override
    @Transactional
    public User createVerifiedUser(CreateUserRequest request) {
        User user = createUserWithRole(request, "ROLE_USER");
        user.markEmailAsVerified();
        User savedUser = userRepository.save(user);
        log.info("Pre-verified user created with ID: {} (FREE+INDIVIDUAL)", savedUser.getId());
        return savedUser;
    }

    // ===== MÉTODOS DE ACTUALIZACIÓN =====

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

    // ===== MÉTODO CORREGIDO PARA UPGRADE =====

    /**
     * ÚNICO MÉTODO DE UPGRADE: FREE+INDIVIDUAL → PRO+PRO_SELLER
     */
    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User upgradeToProSeller(Long userId, UpgradeToProSellerRequest request) {
        log.info("Upgrading user {} from FREE+INDIVIDUAL to PRO+PRO_SELLER", userId);

        User user = getUserById(userId);

        // Validar que el usuario sea FREE + INDIVIDUAL
        if (!user.isFreeIndividual()) {
            throw new IllegalStateException(
                    String.format("User must be FREE+INDIVIDUAL to upgrade. Current: %s+%s",
                            user.getSubscriptionType(), user.getUserType())
            );
        }

        // Realizar upgrade usando el método del dominio
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
        log.info("User {} successfully upgraded to PRO+PRO_SELLER", userId);

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

        // Usar el método del dominio que ya valida si es PRO_SELLER
        user.updateBusinessInfo(
                request.getBusinessName(),
                request.getBusinessDescription(),
                request.getBusinessLogoUrl()
        );

        User savedUser = userRepository.save(user);
        log.info("Business info updated for user {}", userId);

        return savedUser;
    }

    // ===== MÉTODOS DE VERIFICACIÓN DE EMAIL =====

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

    @Override
    @Transactional(readOnly = true)
    public boolean isEmailVerified(String email) {
        User user = userRepository.findByEmail(email);
        return user != null && user.isEmailVerified();
    }

    // ===== MÉTODOS DE ACTIVACIÓN/DESACTIVACIÓN =====

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

    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User deactivateUser(Long userId) {
        log.info("Deactivating user with ID: {}", userId);
        return disableUser(userId);
    }

    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User activateUser(Long userId) {
        log.info("Activating user with ID: {}", userId);
        return enableUser(userId);
    }

    // ===== MÉTODOS DE BÚSQUEDA AVANZADA =====

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

    // ===== MÉTODOS DE VERIFICACIÓN CORREGIDOS =====

    @Override
    @Transactional(readOnly = true)
    public boolean canUpgradeToProSeller(Long userId) {
        try {
            User user = getUserById(userId);
            // Solo puede upgradear si es FREE+INDIVIDUAL y email verificado
            return user.canUpgradeToProSeller();
        } catch (ResourceNotFoundException e) {
            return false;
        }
    }

    @Override
    @Transactional(readOnly = true)
    public boolean canUpgradeSubscription(Long userId) {
        // Redirigir al método real para compatibilidad
        return canUpgradeToProSeller(userId);
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
                user.getPaymentMethod(),
                user.isValidUserConfiguration() // Nuevo campo para validar configuración
        );
    }

    // ===== MÉTODOS DE ESTADÍSTICAS =====

    @Override
    @Transactional(readOnly = true)
    public UserStats getUserStats() {
        long totalUsers = userRepository.count();
        long verifiedUsers = userRepository.countByIsEnabledTrue();
        long unverifiedUsers = totalUsers - verifiedUsers;

        // ESTADÍSTICAS CORREGIDAS CON LÓGICA CONSISTENTE
        long freeUsers = userRepository.countByUserType(UserType.INDIVIDUAL); // FREE = INDIVIDUAL
        long proUsers = userRepository.countByUserType(UserType.PRO_SELLER);  // PRO = PRO_SELLER
        long individualUsers = freeUsers; // Son lo mismo
        long proSellers = proUsers;       // Son lo mismo

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

    // ===== MÉTODOS DE VALIDACIÓN DE CONFIGURACIONES =====

    @Override
    @Transactional(readOnly = true)
    public boolean hasValidConfiguration(Long userId) {
        try {
            User user = getUserById(userId);
            return user.isValidUserConfiguration();
        } catch (ResourceNotFoundException e) {
            return false;
        }
    }

    @Override
    @Transactional(readOnly = true)
    public List<User> findUsersWithInvalidConfigurations() {
        log.debug("Finding users with invalid configurations");
        return userRepository.findAll().stream()
                .filter(user -> !user.isValidUserConfiguration())
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public long countUsersWithInvalidConfigurations() {
        log.debug("Counting users with invalid configurations");
        return userRepository.countUsersWithInvalidConfigurations();
    }

    // ===== MÉTODOS DE CORRECCIÓN MASIVA =====

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public int fixInvalidUserConfigurations() {
        log.info("Starting batch fix of invalid user configurations");

        List<User> invalidUsers = findUsersWithInvalidConfigurations();
        int fixedCount = 0;

        for (User user : invalidUsers) {
            try {
                log.info("Fixing user {} with invalid configuration: {}+{}",
                        user.getId(), user.getSubscriptionType(), user.getUserType());

                // Estrategia de corrección basada en los datos del usuario
                if (user.getSubscriptionType() == SubscriptionType.PRO &&
                        user.getUserType() == UserType.INDIVIDUAL) {

                    // Si tiene datos de negocio, convertir a PRO_SELLER
                    if (hasBusinessData(user)) {
                        user.setUserType(UserType.PRO_SELLER);
                        log.info("Fixed user {} to PRO+PRO_SELLER (has business data)", user.getId());
                    } else {
                        // Si no tiene datos de negocio, convertir a FREE+INDIVIDUAL
                        user.setSubscriptionType(SubscriptionType.FREE);
                        user.setPaymentMethod(null);
                        user.setUpgradedToProAt(null);
                        log.info("Fixed user {} to FREE+INDIVIDUAL (no business data)", user.getId());
                    }

                } else if (user.getSubscriptionType() == SubscriptionType.FREE &&
                        user.getUserType() == UserType.PRO_SELLER) {

                    // Convertir a FREE+INDIVIDUAL y limpiar datos de negocio
                    user.setUserType(UserType.INDIVIDUAL);
                    clearBusinessData(user);
                    log.info("Fixed user {} to FREE+INDIVIDUAL (cleared business data)", user.getId());
                }

                userRepository.save(user);
                fixedCount++;

            } catch (Exception e) {
                log.error("Error fixing user {} configuration: {}", user.getId(), e.getMessage());
            }
        }

        log.info("Completed batch fix: {} users corrected", fixedCount);
        return fixedCount;
    }

    // ===== MÉTODOS DE REPORTES =====

    @Override
    @Transactional(readOnly = true)
    public Map<String, Long> getConfigurationDistribution() {
        Map<String, Long> distribution = new HashMap<>();

        distribution.put("FREE+INDIVIDUAL",
                userRepository.countBySubscriptionTypeAndUserType(SubscriptionType.FREE, UserType.INDIVIDUAL));
        distribution.put("PRO+PRO_SELLER",
                userRepository.countBySubscriptionTypeAndUserType(SubscriptionType.PRO, UserType.PRO_SELLER));

        // Configuraciones inválidas (no deberían existir)
        distribution.put("PRO+INDIVIDUAL",
                userRepository.countBySubscriptionTypeAndUserType(SubscriptionType.PRO, UserType.INDIVIDUAL));
        distribution.put("FREE+PRO_SELLER",
                userRepository.countBySubscriptionTypeAndUserType(SubscriptionType.FREE, UserType.PRO_SELLER));

        return distribution;
    }

    @Override
    @Transactional(readOnly = true)
    public SystemHealthReport getSystemHealthReport() {
        var distribution = getConfigurationDistribution();
        long totalUsers = userRepository.count();
        long validUsers = distribution.get("FREE+INDIVIDUAL") + distribution.get("PRO+PRO_SELLER");
        long invalidUsers = distribution.get("PRO+INDIVIDUAL") + distribution.get("FREE+PRO_SELLER");

        return new SystemHealthReport(
                totalUsers,
                validUsers,
                invalidUsers,
                invalidUsers == 0,
                totalUsers > 0 ? (double) validUsers / totalUsers * 100 : 100.0,
                distribution
        );
    }

    // ===== MÉTODOS AUXILIARES PRIVADOS =====

    /**
     * Verifica si un usuario tiene datos de negocio
     */
    private boolean hasBusinessData(User user) {
        return (user.getBusinessName() != null && !user.getBusinessName().trim().isEmpty()) ||
                (user.getTaxId() != null && !user.getTaxId().trim().isEmpty()) ||
                (user.getFiscalAddress() != null && !user.getFiscalAddress().trim().isEmpty());
    }

    /**
     * Limpia los datos de negocio de un usuario
     */
    private void clearBusinessData(User user) {
        user.setBusinessName(null);
        user.setBusinessDescription(null);
        user.setBusinessLogoUrl(null);
        user.setFiscalAddress(null);
        user.setTaxId(null);
        user.setPaymentMethod(null);
        user.setUpgradedToProAt(null);
    }

    // ===== RECORDS PARA DATOS ESTRUCTURADOS =====

    /**
     * Record para estadísticas de usuarios CORREGIDO
     */
    public record UserStats(
            long totalUsers,
            long verifiedUsers,
            long unverifiedUsers,
            long proUsers,        // = proSellers
            long freeUsers,       // = individualUsers
            long proSellers,      // = proUsers
            long individualUsers  // = freeUsers
    ) {}

    /**
     * Record para información de suscripción CORREGIDO
     */
    public record UserSubscriptionInfo(
            SubscriptionType subscriptionType,
            UserType userType,
            boolean isPro,
            boolean isProSeller,
            boolean canAccessProFeatures,
            LocalDateTime upgradedToProAt,
            String paymentMethod,
            boolean isValidConfiguration // Para detectar configuraciones incorrectas
    ) {}

    /**
     * Record para reporte de salud del sistema
     */
    public record SystemHealthReport(
            long totalUsers,
            long validUsers,
            long invalidUsers,
            boolean isHealthy,
            double healthPercentage,
            Map<String, Long> configurationDistribution
    ) {}


}
