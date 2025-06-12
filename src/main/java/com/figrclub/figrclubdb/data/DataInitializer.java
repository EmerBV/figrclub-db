package com.figrclub.figrclubdb.data;

import com.figrclub.figrclubdb.domain.model.Role;
import com.figrclub.figrclubdb.domain.model.User;
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

            // Crear usuario administrador
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
                    .build();

            // Marcar como verificado
            defaultAdmin.markEmailAsVerified();

            User savedAdmin = userRepository.save(defaultAdmin);

            log.info("✅ Default administrator created successfully!");
            log.info("📧 Email: {}", defaultAdminEmail);
            log.info("🔑 Password: {} (CHANGE THIS IN PRODUCTION!)", defaultAdminPassword);
            log.info("🆔 User ID: {}", savedAdmin.getId());

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
     * Detecta si estamos en un entorno de producción
     */
    private boolean isProductionEnvironment() {
        String activeProfiles = System.getProperty("spring.profiles.active");
        return activeProfiles != null &&
                (activeProfiles.contains("prod") || activeProfiles.contains("production"));
    }
}
