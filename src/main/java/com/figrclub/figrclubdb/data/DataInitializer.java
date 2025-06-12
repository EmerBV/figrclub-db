package com.figrclub.figrclubdb.data;

import com.figrclub.figrclubdb.domain.model.Role;
import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.enums.UserType;
import com.figrclub.figrclubdb.repository.RoleRepository;
import com.figrclub.figrclubdb.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
@Order(1) // Ejecutar primero
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // Configuración del admin por defecto desde application.properties
    @Value("${app.admin.default.email:admin@figrclub.com}")
    private String defaultAdminEmail;

    @Value("${app.admin.default.password:Admin123!}")
    private String defaultAdminPassword;

    @Value("${app.admin.default.first-name:Admin}")
    private String defaultAdminFirstName;

    @Value("${app.admin.default.last-name:FigrClub}")
    private String defaultAdminLastName;

    @Value("${app.admin.default.enabled:true}")
    private boolean createDefaultAdmin;

    @Override
    @Transactional
    public void run(String... args) throws Exception {
        try {
            log.info("Starting data initialization...");

            // 1. Crear roles si no existen
            createRoleIfNotExists("ROLE_USER");
            createRoleIfNotExists("ROLE_ADMIN");

            // 2. Crear administrador por defecto si está habilitado
            if (createDefaultAdmin) {
                createDefaultAdminIfNotExists();
            }

            // 3. Crear usuarios de ejemplo para testing (solo en desarrollo)
            if (isDevEnvironment()) {
                createExampleUsers();
            }

            log.info("Data initialization completed successfully");
        } catch (Exception e) {
            log.error("Error during data initialization: {}", e.getMessage(), e);
            // No lanzar la excepción para que la app pueda arrancar
        }
    }

    private void createRoleIfNotExists(String roleName) {
        try {
            if (roleRepository.findByName(roleName).isEmpty()) {
                Role role = new Role(roleName);
                roleRepository.save(role);
                log.info("Created role: {}", roleName);
            } else {
                log.debug("Role already exists: {}", roleName);
            }
        } catch (Exception e) {
            log.error("Error creating role {}: {}", roleName, e.getMessage());
        }
    }

    private void createDefaultAdminIfNotExists() {
        try {
            // Verificar si ya existe un administrador
            if (userRepository.existsByEmail(defaultAdminEmail)) {
                log.info("Default admin already exists with email: {}", defaultAdminEmail);
                return;
            }

            // Verificar si ya existe algún usuario con rol ADMIN
            long adminCount = userRepository.countByRoleName("ROLE_ADMIN");
            if (adminCount > 0) {
                log.info("Admin users already exist ({}), skipping default admin creation", adminCount);
                return;
            }

            // Obtener rol de administrador
            Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                    .orElseThrow(() -> new RuntimeException("ROLE_ADMIN not found"));

            // Crear usuario administrador con nuevos campos
            User defaultAdmin = User.builder()
                    .firstName(defaultAdminFirstName)
                    .lastName(defaultAdminLastName)
                    .email(defaultAdminEmail)
                    .password(passwordEncoder.encode(defaultAdminPassword))
                    .roles(Set.of(adminRole))
                    .isEnabled(true) // Admin pre-verificado
                    .isAccountNonExpired(true)
                    .isAccountNonLocked(true)
                    .isCredentialsNonExpired(true)
                    // NUEVOS CAMPOS CON VALORES POR DEFECTO
                    .userType(UserType.INDIVIDUAL) // Admin como usuario individual
                    .subscriptionType(SubscriptionType.PRO) // Admin con suscripción PRO
                    .phone("+34 600 000 000")
                    .country("España")
                    .city("Madrid")
                    .build();

            // Marcar como verificado
            defaultAdmin.markEmailAsVerified();

            User savedAdmin = userRepository.save(defaultAdmin);

            log.info("✅ Default administrator created successfully!");
            log.info("📧 Email: {}", defaultAdminEmail);
            log.info("🔑 Password: {} (CHANGE THIS IN PRODUCTION!)", defaultAdminPassword);
            log.info("🆔 User ID: {}", savedAdmin.getId());
            log.info("👤 User Type: {}", savedAdmin.getUserType());
            log.info("💳 Subscription: {}", savedAdmin.getSubscriptionType());

            // Warning de seguridad
            if (isProductionEnvironment()) {
                log.warn("⚠️  WARNING: Default admin created in PRODUCTION environment!");
                log.warn("⚠️  IMMEDIATELY change the default password: {}", defaultAdminEmail);
            }

        } catch (Exception e) {
            log.error("Error creating default administrator: {}", e.getMessage(), e);
        }
    }

    /**
     * Crea usuarios de ejemplo para testing (solo en desarrollo)
     */
    private void createExampleUsers() {
        try {
            log.info("Creating example users for development environment...");

            Role userRole = roleRepository.findByName("ROLE_USER")
                    .orElseThrow(() -> new RuntimeException("ROLE_USER not found"));

            // 1. Usuario FREE Individual verificado
            createExampleUserIfNotExists(
                    "user.free@figrclub.com",
                    "Usuario",
                    "Free",
                    "FreeUser123!",
                    userRole,
                    UserType.INDIVIDUAL,
                    SubscriptionType.FREE,
                    true, // verificado
                    "+34 600 111 111",
                    "España",
                    "Barcelona"
            );

            // 2. Usuario PRO Individual verificado
            createExampleUserIfNotExists(
                    "user.pro@figrclub.com",
                    "Usuario",
                    "Pro",
                    "ProUser123!",
                    userRole,
                    UserType.INDIVIDUAL,
                    SubscriptionType.PRO,
                    true, // verificado
                    "+34 600 222 222",
                    "España",
                    "Valencia"
            );

            // 3. Vendedor Profesional verificado
            User proSeller = createExampleUserIfNotExists(
                    "seller.pro@figrclub.com",
                    "Vendedor",
                    "Profesional",
                    "ProSeller123!",
                    userRole,
                    UserType.PRO_SELLER,
                    SubscriptionType.PRO,
                    true, // verificado
                    "+34 600 333 333",
                    "España",
                    "Sevilla"
            );

            // Agregar información de negocio al vendedor profesional
            if (proSeller != null) {
                proSeller.setBusinessName("TechStore Pro");
                proSeller.setBusinessDescription("Tienda especializada en tecnología y gadgets");
                proSeller.setFiscalAddress("Calle Tecnología 123, 41001 Sevilla, España");
                proSeller.setTaxId("B12345678");
                proSeller.setPaymentMethod("STRIPE");
                userRepository.save(proSeller);
                log.info("Business info added to Pro Seller: {}", proSeller.getEmail());
            }

            // 4. Usuario no verificado
            createExampleUserIfNotExists(
                    "user.unverified@figrclub.com",
                    "Usuario",
                    "NoVerificado",
                    "Unverified123!",
                    userRole,
                    UserType.INDIVIDUAL,
                    SubscriptionType.FREE,
                    false, // NO verificado
                    null,
                    null,
                    null
            );

            log.info("Example users created successfully!");

        } catch (Exception e) {
            log.error("Error creating example users: {}", e.getMessage(), e);
        }
    }

    private User createExampleUserIfNotExists(String email, String firstName, String lastName,
                                              String password, Role role, UserType userType,
                                              SubscriptionType subscriptionType, boolean verified,
                                              String phone, String country, String city) {
        try {
            if (userRepository.existsByEmail(email)) {
                log.debug("Example user already exists: {}", email);
                return userRepository.findByEmail(email);
            }

            User user = User.builder()
                    .firstName(firstName)
                    .lastName(lastName)
                    .email(email)
                    .password(passwordEncoder.encode(password))
                    .roles(Set.of(role))
                    .userType(userType)
                    .subscriptionType(subscriptionType)
                    .isEnabled(verified)
                    .isAccountNonExpired(true)
                    .isAccountNonLocked(true)
                    .isCredentialsNonExpired(true)
                    .phone(phone)
                    .country(country)
                    .city(city)
                    .birthDate(LocalDate.of(1990, 1, 1)) // Fecha de ejemplo
                    .build();

            if (verified) {
                user.markEmailAsVerified();
            }

            User savedUser = userRepository.save(user);
            log.info("Created example user: {} ({})", email, userType);
            return savedUser;

        } catch (Exception e) {
            log.error("Error creating example user {}: {}", email, e.getMessage());
            return null;
        }
    }

    /**
     * Detecta si estamos en un entorno de desarrollo
     */
    private boolean isDevEnvironment() {
        String activeProfiles = System.getProperty("spring.profiles.active");
        return activeProfiles == null ||
                activeProfiles.contains("dev") ||
                activeProfiles.contains("development") ||
                activeProfiles.isEmpty(); // Por defecto es desarrollo
    }

    /**
     * Detecta si estamos en un entorno de producción
     */
    private boolean isProductionEnvironment() {
        String activeProfiles = System.getProperty("spring.profiles.active");
        return activeProfiles != null &&
                (activeProfiles.contains("prod") || activeProfiles.contains("production"));
    }
}
