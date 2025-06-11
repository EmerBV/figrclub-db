package com.figrclub.figrclubdb.config;

import com.figrclub.figrclubdb.service.auth.JwtBlacklistService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Tareas programadas para mantenimiento del sistema JWT
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtCleanupTask {

    private final JwtBlacklistService jwtBlacklistService;

    /**
     * Limpia tokens expirados de la blacklist cada hora
     */
    @Scheduled(fixedRate = 3600000) // Cada hora (3600000 ms)
    public void cleanupExpiredTokens() {
        try {
            log.debug("Starting JWT blacklist cleanup");
            int sizeBefore = jwtBlacklistService.getBlacklistSize();

            jwtBlacklistService.cleanupExpiredTokens();

            int sizeAfter = jwtBlacklistService.getBlacklistSize();
            int removed = sizeBefore - sizeAfter;

            if (removed > 0) {
                log.info("JWT cleanup completed: {} expired tokens removed, {} remaining",
                        removed, sizeAfter);
            } else {
                log.debug("JWT cleanup completed: no expired tokens found");
            }

        } catch (Exception e) {
            log.error("Error during JWT blacklist cleanup: {}", e.getMessage(), e);
        }
    }

    /**
     * Reporte de estadísticas de la blacklist cada 6 horas
     */
    @Scheduled(fixedRate = 21600000) // Cada 6 horas
    public void reportBlacklistStats() {
        try {
            int blacklistSize = jwtBlacklistService.getBlacklistSize();
            log.info("JWT Blacklist Statistics: {} tokens currently blacklisted", blacklistSize);

            // En producción, aquí podrías enviar métricas a sistemas de monitoreo
            // como Prometheus, CloudWatch, etc.

        } catch (Exception e) {
            log.error("Error generating JWT blacklist statistics: {}", e.getMessage(), e);
        }
    }
}
