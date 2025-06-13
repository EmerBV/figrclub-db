package com.figrclub.figrclubdb.service.user;

import com.figrclub.figrclubdb.domain.model.Role;
import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
import com.figrclub.figrclubdb.dto.UserStatistics;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.enums.UserType;
import com.figrclub.figrclubdb.exceptions.AlreadyExistsException;
import com.figrclub.figrclubdb.exceptions.ResourceNotFoundException;
import com.figrclub.figrclubdb.exceptions.RoleModificationException;
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

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Servicio de usuarios ACTUALIZADO con roles inmutables:
 * - Los roles se asignan SOLO durante la creación del usuario
 * - NO se pueden modificar roles después de la creación
 * - Se mantiene toda la funcionalidad de consulta y gestión de usuarios
 * - Roles: USER, ADMIN (inmutables)
 * - Tiers: FREE+INDIVIDUAL, PRO+PRO_SELLER (modificables)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserService implements IUserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final ModelMapper modelMapper;

    // ===== MÉTODOS DE BÚSQUEDA BÁSICA =====

    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "#userId")
    public User getUserById(Long userId) {
        log.debug("Fetching user by ID: {}", userId);
        return userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<User> findByEmail(String email) {
        log.debug("Finding user by email: {}", email);
        return Optional.ofNullable(userRepository.findByEmail(email));
    }

    @Override
    @Transactional(readOnly = true)
    public boolean existsByEmail(String email) {
        log.debug("Checking if user exists with email: {}", email);
        return userRepository.existsByEmail(email);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> searchUsers(String searchTerm, Pageable pageable) {
        log.debug("Searching users with term: {}", searchTerm);
        return userRepository.findByEmailContainingIgnoreCaseOrFirstNameContainingIgnoreCaseOrLastNameContainingIgnoreCase(
                searchTerm, searchTerm, searchTerm, pageable);
    }

    // ===== MÉTODOS DE LISTADO CON PAGINACIÓN =====

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
        return userRepository.findByIsEnabledTrueAndEmailVerifiedAtIsNotNull(pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findVerifiedUsers(Pageable pageable) {
        log.debug("Finding verified users with pagination: {}", pageable);
        return userRepository.findByEmailVerifiedAtIsNotNull(pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findUnverifiedUsers(Pageable pageable) {
        log.debug("Finding unverified users with pagination: {}", pageable);
        return userRepository.findByEmailVerifiedAtIsNull(pageable);
    }

    // ===== MÉTODOS DE CONSULTA DE ROLES (SOLO LECTURA) =====

    @Override
    @Transactional(readOnly = true)
    public Page<User> findUsersByRole(String roleName, Pageable pageable) {
        log.debug("Finding users by role: {} with pagination: {}", roleName, pageable);
        return userRepository.findByRoleName(roleName, pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findAdminUsers(Pageable pageable) {
        log.debug("Finding admin users with pagination: {}", pageable);
        return userRepository.findByRoleName("ROLE_ADMIN", pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findRegularUsers(Pageable pageable) {
        log.debug("Finding regular users with pagination: {}", pageable);
        return userRepository.findByRoleName("ROLE_USER", pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public long countUsersByRole(String roleName) {
        log.debug("Counting users by role: {}", roleName);
        return userRepository.countByRoleName(roleName);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean userHasRole(Long userId, String roleName) {
        log.debug("Checking if user {} has role: {}", userId, roleName);
        User user = getUserById(userId);
        return user.hasRole(roleName);
    }

    @Override
    @Transactional(readOnly = true)
    public Role getUserRole(Long userId) {
        log.debug("Getting role for user: {}", userId);
        User user = getUserById(userId);
        return user.getRole();
    }

    @Override
    @Transactional(readOnly = true)
    public String getUserRoleName(Long userId) {
        log.debug("Getting role name for user: {}", userId);
        User user = getUserById(userId);
        return user.getRoleName();
    }

    // ===== MÉTODOS DE USUARIOS POR SUSCRIPCIÓN Y TIPO =====

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
        log.debug("Finding Pro Sellers with pagination: {}", pageable);
        return userRepository.findByUserType(UserType.PRO_SELLER, pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findIndividualUsers(Pageable pageable) {
        log.debug("Finding Individual users with pagination: {}", pageable);
        return userRepository.findByUserType(UserType.INDIVIDUAL, pageable);
    }

    // ===== MÉTODOS COMBINADOS: ROLES + TIERS =====

    @Override
    @Transactional(readOnly = true)
    public Page<User> findAdminProSellers(Pageable pageable) {
        log.debug("Finding admin Pro Sellers with pagination: {}", pageable);
        return userRepository.findAdminProSellers(pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findRegularProSellers(Pageable pageable) {
        log.debug("Finding regular Pro Sellers with pagination: {}", pageable);
        return userRepository.findRegularProSellers(pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findAdminBasicUsers(Pageable pageable) {
        log.debug("Finding admin basic users with pagination: {}", pageable);
        return userRepository.findAdminBasicUsers(pageable);
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

        // CORREGIDO: Mapear rol único en lugar de lista de roles
        if (user.getRole() != null) {
            userDto.setRole(user.getRole().getName());
            userDto.setRoleId(user.getRole().getId());
            userDto.setRoleDescription(user.getRole().getDescription());
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

    // ===== MÉTODOS DE CREACIÓN CON ROL INMUTABLE =====

    @Override
    @Transactional
    public User createUser(CreateUserRequest request) {
        log.info("Creating regular user: {}", request.getEmail());
        return createUserWithRole(request, "ROLE_USER");
    }

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public User createAdminUser(CreateUserRequest request) {
        log.info("Creating admin user: {}", request.getEmail());
        return createUserWithRole(request, "ROLE_ADMIN");
    }

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public User createVerifiedUser(CreateUserRequest request) {
        log.info("Creating verified user: {}", request.getEmail());
        User user = createUserWithRole(request, "ROLE_USER");
        user.setEmailVerifiedAt(LocalDateTime.now());
        user.setEnabled(true);
        return userRepository.save(user);
    }

    @Override
    @Transactional
    public User createUserWithRole(CreateUserRequest request, String roleName) {
        log.info("Creating user with role {}: {}", roleName, request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Attempt to create user with existing email: {}", request.getEmail());
            throw new AlreadyExistsException("User already exists with email: " + request.getEmail());
        }

        // Buscar el rol
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + roleName));

        // Crear usuario con rol inmutable usando constructor manual
        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(role); // ROL ASIGNADO EN LA CREACIÓN
        user.setUserType(UserType.INDIVIDUAL);
        user.setSubscriptionType(SubscriptionType.FREE);
        user.setEnabled(false);
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setCredentialsNonExpired(true);

        // Si es admin, habilitar automáticamente
        if ("ROLE_ADMIN".equals(roleName)) {
            user.setEnabled(true);
            user.setEmailVerifiedAt(LocalDateTime.now());
        }

        User savedUser = userRepository.save(user);
        log.info("User created successfully with ID: {} and role: {}", savedUser.getId(), roleName);
        return savedUser;
    }

    // ===== MÉTODOS DE ACTUALIZACIÓN (SIN MODIFICACIÓN DE ROLES) =====

    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User updateUser(UserUpdateRequest request, Long userId) {
        log.info("Updating user: {}", userId);

        User user = getUserById(userId);

        // Actualizar campos básicos (sin tocar el rol)
        if (request.getFirstName() != null) {
            user.setFirstName(request.getFirstName());
        }
        if (request.getLastName() != null) {
            user.setLastName(request.getLastName());
        }
        if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmail(request.getEmail())) {
                throw new AlreadyExistsException("Email already exists: " + request.getEmail());
            }
            user.setEmail(request.getEmail());
        }

        // Actualizar campos adicionales si están presentes en el request
        if (request.getPhone() != null) {
            user.setPhone(request.getPhone());
        }
        if (request.getCountry() != null) {
            user.setCountry(request.getCountry());
        }
        if (request.getCity() != null) {
            user.setCity(request.getCity());
        }
        if (request.getBirthDate() != null) {
            user.setBirthDate(request.getBirthDate());
        }

        // Actualizar password si se proporciona
        if (request.getPassword() != null && !request.getPassword().trim().isEmpty()) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }

        // Actualizar estado (solo para admins)
        if (request.getEnabled() != null) {
            user.setEnabled(request.getEnabled());
        }

        // Si es vendedor profesional, actualizar información de negocio
        if (user.isProSeller() && request.getBusinessName() != null) {
            user.setBusinessName(request.getBusinessName());
        }
        if (user.isProSeller() && request.getBusinessDescription() != null) {
            user.setBusinessDescription(request.getBusinessDescription());
        }
        if (user.isProSeller() && request.getFiscalAddress() != null) {
            user.setFiscalAddress(request.getFiscalAddress());
        }
        if (user.isProSeller() && request.getTaxId() != null) {
            user.setTaxId(request.getTaxId());
        }
        if (user.isProSeller() && request.getPaymentMethod() != null) {
            user.setPaymentMethod(request.getPaymentMethod());
        }

        // IMPORTANTE: El rol NO se toca nunca
        log.debug("User role preserved during update: {}", user.getRoleName());

        User updatedUser = userRepository.save(user);
        log.info("User updated successfully: {}", userId);
        return updatedUser;
    }

    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User updateContactInfo(Long userId, UpdateContactInfoRequest request) {
        log.info("Updating contact info for user: {}", userId);

        User user = getUserById(userId);

        user.setPhone(request.getPhone());
        user.setCountry(request.getCountry());
        user.setCity(request.getCity());
        user.setBirthDate(request.getBirthDate());

        User updatedUser = userRepository.save(user);
        log.info("Contact info updated for user: {}", userId);
        return updatedUser;
    }

    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User updateBusinessInfo(Long userId, UpdateBusinessInfoRequest request) {
        log.info("Updating business info for user: {}", userId);

        User user = getUserById(userId);

        if (!user.isProSeller()) {
            throw new IllegalStateException("User must be a professional seller to update business information");
        }

        user.setBusinessName(request.getBusinessName());
        user.setBusinessDescription(request.getBusinessDescription());
        user.setBusinessLogoUrl(request.getBusinessLogoUrl());
        user.setFiscalAddress(request.getFiscalAddress());
        user.setTaxId(request.getTaxId());
        user.setPaymentMethod(request.getPaymentMethod());

        User updatedUser = userRepository.save(user);
        log.info("Business info updated for user: {}", userId);
        return updatedUser;
    }

    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(Long userId) {
        log.info("Deleting user: {}", userId);

        User user = getUserById(userId);
        userRepository.delete(user);
        log.info("User deleted successfully: {}", userId);
    }

    // ===== MÉTODO ÚNICO DE UPGRADE =====

    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User upgradeToProSeller(Long userId, UpgradeToProSellerRequest request) {
        log.info("Upgrading user {} to Pro Seller", userId);

        User user = getUserById(userId);

        if (!canUpgradeToProSeller(userId)) {
            throw new IllegalStateException("User cannot be upgraded to Pro Seller");
        }

        // Cambiar tipo y suscripción (NO el rol)
        user.setUserType(UserType.PRO_SELLER);
        user.setSubscriptionType(SubscriptionType.PRO);
        user.setUpgradedToProAt(LocalDateTime.now());

        // Establecer información de negocio
        user.setBusinessName(request.getBusinessName());
        user.setBusinessDescription(request.getBusinessDescription());
        user.setFiscalAddress(request.getFiscalAddress());
        user.setTaxId(request.getTaxId());

        User upgradedUser = userRepository.save(user);
        log.info("User {} upgraded to Pro Seller successfully. Role preserved: {}",
                userId, user.getRoleName());
        return upgradedUser;
    }

    // ===== MÉTODOS DE VALIDACIÓN Y SEGURIDAD =====

    @Override
    @Transactional(readOnly = true)
    public boolean canUpgradeToProSeller(Long userId) {
        User user = getUserById(userId);
        return user.getUserType() == UserType.INDIVIDUAL &&
                user.getSubscriptionType() == SubscriptionType.FREE &&
                user.isActive();
    }

    @Override
    @Transactional(readOnly = true)
    public boolean canAccessAdminFeatures(Long userId) {
        return userHasRole(userId, "ROLE_ADMIN");
    }

    @Override
    @Transactional(readOnly = true)
    public boolean canViewUserDetails(Long currentUserId, Long targetUserId) {
        return currentUserId.equals(targetUserId) || canAccessAdminFeatures(currentUserId);
    }

    // ===== MÉTODOS DE ESTADÍSTICAS Y REPORTES =====

    @Override
    @Transactional(readOnly = true)
    public Map<String, Long> getUserStatsByRole() {
        Map<String, Long> stats = new HashMap<>();
        stats.put("ROLE_USER", countUsersByRole("ROLE_USER"));
        stats.put("ROLE_ADMIN", countUsersByRole("ROLE_ADMIN"));
        return stats;
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, Long> getUserStatsByTypeAndSubscription() {
        Map<String, Long> stats = new HashMap<>();
        stats.put("INDIVIDUAL_FREE", userRepository.countByUserTypeAndSubscriptionType(
                UserType.INDIVIDUAL, SubscriptionType.FREE));
        stats.put("PRO_SELLER_PRO", userRepository.countByUserTypeAndSubscriptionType(
                UserType.PRO_SELLER, SubscriptionType.PRO));
        return stats;
    }

    @Override
    @Transactional(readOnly = true)
    public long countActiveUsers() {
        return userRepository.countByIsEnabledTrueAndEmailVerifiedAtIsNotNull();
    }

    @Override
    @Transactional(readOnly = true)
    public long countVerifiedUsers() {
        return userRepository.countByEmailVerifiedAtIsNotNull();
    }

    @Override
    @Transactional(readOnly = true)
    public long countAdminUsers() {
        return countUsersByRole("ROLE_ADMIN");
    }

    @Override
    @Transactional(readOnly = true)
    public long countRegularUsers() {
        return countUsersByRole("ROLE_USER");
    }

    // ===== MÉTODOS DE INFORMACIÓN DEL SISTEMA =====

    @Override
    public String getRoleImmutabilityInfo() {
        return "User roles are immutable and cannot be changed after account creation. " +
                "This ensures data integrity and security. Roles can only be assigned during user creation.";
    }

    @Override
    @Transactional(readOnly = true)
    public List<Role> getAvailableRoles() {
        return roleRepository.findAll();
    }

    @Override
    @Transactional(readOnly = true)
    public boolean roleExists(String roleName) {
        return roleRepository.findByName(roleName).isPresent();
    }

    // ===== MÉTODOS ADICIONALES REQUERIDOS =====

    /**
     * Obtiene información de suscripción del usuario
     */
    @Transactional(readOnly = true)
    public UserSubscriptionInfo getSubscriptionInfo(Long userId) {
        User user = getUserById(userId);
        return new UserSubscriptionInfo(
                user.getSubscriptionType(),
                user.getUserType(),
                user.getUpgradedToProAt(),
                user.isProSeller()
        );
    }

    /**
     * Verifica si un usuario puede ser promovido a admin
     */
    public boolean canPromoteToAdmin(Long userId) {
        // Los roles son inmutables, por lo que no se puede promover
        return false;
    }

    /**
     * Verifica si se pueden revocar privilegios de admin
     */
    public boolean canRevokeAdminPrivileges(Long userId) {
        // Los roles son inmutables, por lo que no se pueden revocar
        return false;
    }

    /**
     * Obtiene estadísticas completas de usuarios
     */
    public UserStatistics getUserStatistics() {
        return new UserStatistics(
                userRepository.count(),
                countActiveUsers(),
                countVerifiedUsers(),
                countAdminUsers(),
                countRegularUsers(),
                userRepository.countByUserType(UserType.PRO_SELLER),
                userRepository.countByUserType(UserType.INDIVIDUAL),
                userRepository.countBySubscriptionType(SubscriptionType.FREE),
                userRepository.countBySubscriptionType(SubscriptionType.PRO)
        );
    }

    /**
     * Clase interna para información de suscripción
     */
    public static class UserSubscriptionInfo {
        private final SubscriptionType subscriptionType;
        private final UserType userType;
        private final LocalDateTime upgradedAt;
        private final boolean isProSeller;

        public UserSubscriptionInfo(SubscriptionType subscriptionType, UserType userType,
                                    LocalDateTime upgradedAt, boolean isProSeller) {
            this.subscriptionType = subscriptionType;
            this.userType = userType;
            this.upgradedAt = upgradedAt;
            this.isProSeller = isProSeller;
        }

        // Getters
        public SubscriptionType getSubscriptionType() { return subscriptionType; }
        public UserType getUserType() { return userType; }
        public LocalDateTime getUpgradedAt() { return upgradedAt; }
        public boolean isProSeller() { return isProSeller; }
    }
}