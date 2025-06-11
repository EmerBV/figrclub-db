package com.figrclub.figrclubdb.service.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Servicio para gestionar la blacklist de tokens JWT
 * Permite invalidar tokens específicos durante el logout
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class JwtBlacklistService {

    // En producción, esto debería usar Redis para persistencia y escalabilidad
    private final ConcurrentMap<String, LocalDateTime> blacklistedTokens = new ConcurrentHashMap<>();

    /**
     * Agrega un token a la blacklist
     * @param tokenId Identificador único del token (puede ser el jti claim o hash del token)
     * @param expirationTime Tiempo de expiración del token
     */
    public void blacklistToken(String tokenId, LocalDateTime expirationTime) {
        blacklistedTokens.put(tokenId, expirationTime);
        log.debug("Token {} added to blacklist, expires at: {}", tokenId, expirationTime);
    }

    /**
     * Verifica si un token está en la blacklist
     * @param tokenId Identificador del token
     * @return true si el token está blacklisted, false si no
     */
    public boolean isTokenBlacklisted(String tokenId) {
        LocalDateTime expirationTime = blacklistedTokens.get(tokenId);

        if (expirationTime == null) {
            return false;
        }

        // Si el token ha expirado, lo removemos de la blacklist
        if (LocalDateTime.now().isAfter(expirationTime)) {
            blacklistedTokens.remove(tokenId);
            log.debug("Expired token {} removed from blacklist", tokenId);
            return false;
        }

        return true;
    }

    /**
     * Limpia tokens expirados de la blacklist
     * Método para mantenimiento automático
     */
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        int initialSize = blacklistedTokens.size();

        blacklistedTokens.entrySet().removeIf(entry -> now.isAfter(entry.getValue()));

        int removedCount = initialSize - blacklistedTokens.size();
        if (removedCount > 0) {
            log.info("Cleaned up {} expired tokens from blacklist", removedCount);
        }
    }

    /**
     * Obtiene el número de tokens en la blacklist
     * @return Número de tokens blacklisted
     */
    public int getBlacklistSize() {
        return blacklistedTokens.size();
    }

    /**
     * Limpia todos los tokens de la blacklist (solo para testing)
     */
    public void clearBlacklist() {
        blacklistedTokens.clear();
        log.warn("JWT Blacklist cleared - this should only happen in tests");
    }
}
