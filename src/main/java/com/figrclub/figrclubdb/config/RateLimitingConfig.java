package com.figrclub.figrclubdb.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import lombok.Data;

import java.util.Map;
import java.util.Set;

@Configuration
@ConfigurationProperties(prefix = "app.security.rate-limit")
@Data
public class RateLimitingConfig {

    private boolean enabled = true;
    private int maxAttemptsPerIp = 10;
    private int maxAttemptsPerUser = 5;
    private int windowMinutes = 15;
    private int blockDurationMinutes = 30;
    private boolean progressiveBlock = true;
    private Set<String> whitelistIps = Set.of("127.0.0.1", "::1");

    // Configuraciones específicas por tipo de intento
    private Map<String, AttemptTypeConfig> attemptTypes = Map.of(
            "login", new AttemptTypeConfig(10, 5, 15, 30),
            "password-reset", new AttemptTypeConfig(5, 3, 60, 60),
            "registration", new AttemptTypeConfig(3, 1, 30, 120)
    );

    @Data
    public static class AttemptTypeConfig {
        private int maxAttemptsPerIp;
        private int maxAttemptsPerUser;
        private int windowMinutes;
        private int blockDurationMinutes;

        public AttemptTypeConfig() {}

        public AttemptTypeConfig(int maxAttemptsPerIp, int maxAttemptsPerUser,
                                 int windowMinutes, int blockDurationMinutes) {
            this.maxAttemptsPerIp = maxAttemptsPerIp;
            this.maxAttemptsPerUser = maxAttemptsPerUser;
            this.windowMinutes = windowMinutes;
            this.blockDurationMinutes = blockDurationMinutes;
        }
    }

    /**
     * Obtiene la configuración para un tipo específico de intento
     */
    public AttemptTypeConfig getConfigForAttemptType(String attemptType) {
        return attemptTypes.getOrDefault(attemptType.toLowerCase(),
                new AttemptTypeConfig(maxAttemptsPerIp, maxAttemptsPerUser, windowMinutes, blockDurationMinutes));
    }
}
