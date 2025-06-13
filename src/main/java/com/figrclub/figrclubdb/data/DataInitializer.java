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


@Component
@RequiredArgsConstructor
@Slf4j
@Order(1)
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

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
            log.info("Starting data initialization with IMMUTABLE ROLES system...");

            createRoleIfNotExists("ROLE_USER", "Regular user role with standard access");
            createRoleIfNotExists("ROLE_ADMIN", "Administrator role with full system access");

            if (createDefaultAdmin) {
                createDefaultAdminIfNotExists();
            }

            if (isDevEnvironment()) {
                createExampleUsers();
            }

            log.info("✅ Data initialization completed successfully with IMMUTABLE ROLES");
        } catch (Exception e) {
            log.error("❌ Error during data initialization: {}", e.getMessage(), e);
        }
    }

    private void createRoleIfNotExists(String roleName, String description) {
        try {
            if (roleRepository.findByName(roleName).isEmpty()) {
                Role role = new Role(roleName, description);
                roleRepository.save(role);
                log.info("✅ Created role: {} - {}", roleName, description);
            } else {
                log.debug("Role already exists: {}", roleName);
            }
        } catch (Exception e) {
            log.error("❌ Error creating role {}: {}", roleName, e.getMessage());
        }
    }

    private void createDefaultAdminIfNotExists() {
        try {

            if (userRepository.existsByEmail(defaultAdminEmail)) {
                log.info("Default admin already exists with email: {}", defaultAdminEmail);
                return;
            }

            long adminCount = userRepository.countByRoleName("ROLE_ADMIN");
            if (adminCount > 0) {
                log.info("Admin users already exist ({}), skipping default admin creation", adminCount);
                return;
            }

            Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                    .orElseThrow(() -> new RuntimeException("ROLE_ADMIN not found"));

            User defaultAdmin = new User();
            defaultAdmin.setFirstName(defaultAdminFirstName);
            defaultAdmin.setLastName(defaultAdminLastName);
            defaultAdmin.setEmail(defaultAdminEmail);
            defaultAdmin.setPassword(passwordEncoder.encode(defaultAdminPassword));
            defaultAdmin.setRole(adminRole);
            defaultAdmin.setEnabled(true);
            defaultAdmin.setAccountNonExpired(true);
            defaultAdmin.setAccountNonLocked(true);
            defaultAdmin.setCredentialsNonExpired(true);

            defaultAdmin.setUserType(UserType.INDIVIDUAL);
            defaultAdmin.setSubscriptionType(SubscriptionType.FREE);
            defaultAdmin.setPhone("+34 600 000 000");
            defaultAdmin.setCountry("España");
            defaultAdmin.setCity("Madrid");

            defaultAdmin.markEmailAsVerified();

            User savedAdmin = userRepository.save(defaultAdmin);

            log.info("✅ Default administrator created successfully!");
            log.info("📧 Email: {}", savedAdmin.getEmail());
            log.info("🔐 Password: {} (change this in production!)", defaultAdminPassword);
            log.info("👤 Role: {}", savedAdmin.getRoleName());
            log.info("🎫 Tier: {} + {}", savedAdmin.getSubscriptionType(), savedAdmin.getUserType());
            log.info("🔧 Config Valid: {}", savedAdmin.isValidUserConfiguration());

        } catch (Exception e) {
            log.error("❌ Error creating default admin: {}", e.getMessage(), e);
        }
    }

    private void createExampleUsers() {
        try {
            log.info("Creating example users for development...");

            Role userRole = roleRepository.findByName("ROLE_USER")
                    .orElseThrow(() -> new RuntimeException("ROLE_USER not found"));
            Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                    .orElseThrow(() -> new RuntimeException("ROLE_ADMIN not found"));

            if (!userRepository.existsByEmail("user@example.com")) {
                User regularUser = new User();
                regularUser.setFirstName("Juan");
                regularUser.setLastName("Pérez");
                regularUser.setEmail("user@example.com");
                regularUser.setPassword(passwordEncoder.encode("User123!"));
                regularUser.setRole(userRole);
                regularUser.setUserType(UserType.INDIVIDUAL);
                regularUser.setSubscriptionType(SubscriptionType.FREE);
                regularUser.setEnabled(true);
                regularUser.setAccountNonExpired(true);
                regularUser.setAccountNonLocked(true);
                regularUser.setCredentialsNonExpired(true);
                regularUser.setPhone("+34 600 111 111");
                regularUser.setCountry("España");
                regularUser.setCity("Barcelona");
                regularUser.setBirthDate(LocalDate.of(1990, 5, 15));

                regularUser.markEmailAsVerified();
                userRepository.save(regularUser);
                log.info("✅ Created regular user: user@example.com (ROLE_USER + FREE + INDIVIDUAL)");
            }

            if (!userRepository.existsByEmail("proseller@example.com")) {
                User proSeller = new User();
                proSeller.setFirstName("María");
                proSeller.setLastName("García");
                proSeller.setEmail("proseller@example.com");
                proSeller.setPassword(passwordEncoder.encode("ProSeller123!"));
                proSeller.setRole(userRole);
                proSeller.setUserType(UserType.PRO_SELLER);
                proSeller.setSubscriptionType(SubscriptionType.PRO);
                proSeller.setEnabled(true);
                proSeller.setAccountNonExpired(true);
                proSeller.setAccountNonLocked(true);
                proSeller.setCredentialsNonExpired(true);
                proSeller.setPhone("+34 600 222 222");
                proSeller.setCountry("España");
                proSeller.setCity("Madrid");
                proSeller.setBirthDate(LocalDate.of(1985, 8, 22));

                proSeller.updateBusinessInfo("TechStore Pro",
                        "Tienda especializada en tecnología y gadgets",
                        null);
                proSeller.setFiscalAddress("Calle Tecnología 123, Madrid");
                proSeller.setTaxId("B12345678");
                proSeller.setPaymentMethod("Transferencia bancaria");

                proSeller.markEmailAsVerified();
                userRepository.save(proSeller);
                log.info("✅ Created pro seller: proseller@example.com (ROLE_USER + PRO + PRO_SELLER)");
            }

            if (!userRepository.existsByEmail("adminpro@example.com")) {
                User adminProSeller = new User();
                adminProSeller.setFirstName("Carlos");
                adminProSeller.setLastName("Administrador");
                adminProSeller.setEmail("adminpro@example.com");
                adminProSeller.setPassword(passwordEncoder.encode("AdminPro123!"));
                adminProSeller.setRole(adminRole);
                adminProSeller.setUserType(UserType.PRO_SELLER);
                adminProSeller.setSubscriptionType(SubscriptionType.PRO);
                adminProSeller.setEnabled(true);
                adminProSeller.setAccountNonExpired(true);
                adminProSeller.setAccountNonLocked(true);
                adminProSeller.setCredentialsNonExpired(true);
                adminProSeller.setPhone("+34 600 333 333");
                adminProSeller.setCountry("España");
                adminProSeller.setCity("Valencia");

                adminProSeller.setBusinessName("AdminStore Enterprise");
                adminProSeller.setBusinessDescription("Empresa de administración y ventas");
                adminProSeller.setFiscalAddress("Avenida Admin 456, Valencia");
                adminProSeller.setTaxId("B87654321");
                adminProSeller.setPaymentMethod("Múltiples métodos");

                adminProSeller.markEmailAsVerified();
                userRepository.save(adminProSeller);
                log.info("✅ Created admin pro seller: adminpro@example.com (ROLE_ADMIN + PRO + PRO_SELLER)");
            }

            if (!userRepository.existsByEmail("upgrade@example.com")) {
                User upgradeUser = new User();
                upgradeUser.setFirstName("Ana");
                upgradeUser.setLastName("Candidata");
                upgradeUser.setEmail("upgrade@example.com");
                upgradeUser.setPassword(passwordEncoder.encode("Upgrade123!"));
                upgradeUser.setRole(userRole); // Rol USER
                upgradeUser.setUserType(UserType.INDIVIDUAL);
                upgradeUser.setSubscriptionType(SubscriptionType.FREE);
                upgradeUser.setEnabled(true);
                upgradeUser.setAccountNonExpired(true);
                upgradeUser.setAccountNonLocked(true);
                upgradeUser.setCredentialsNonExpired(true);
                upgradeUser.setPhone("+34 600 444 444");
                upgradeUser.setCountry("España");
                upgradeUser.setCity("Sevilla");
                upgradeUser.setBirthDate(LocalDate.of(1992, 12, 3));

                upgradeUser.markEmailAsVerified();
                userRepository.save(upgradeUser);
                log.info("✅ Created upgrade candidate: upgrade@example.com (ROLE_USER + FREE + INDIVIDUAL)");
            }

            log.info("✅ Example users created successfully for development");

        } catch (Exception e) {
            log.error("❌ Error creating example users: {}", e.getMessage(), e);
        }
    }

    private boolean isDevEnvironment() {
        String[] activeProfiles = System.getProperty("spring.profiles.active", "").split(",");
        for (String profile : activeProfiles) {
            if ("dev".equalsIgnoreCase(profile.trim()) || "development".equalsIgnoreCase(profile.trim())) {
                return true;
            }
        }
        return false;
    }
}