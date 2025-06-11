package com.figrclub.figrclubdb.service.ratelimit;

import com.figrclub.figrclubdb.domain.model.LoginAttempt;
import com.figrclub.figrclubdb.dto.RateLimitInfo;
import com.figrclub.figrclubdb.enums.AttemptType;

import java.util.List;

public interface IRateLimitingService {

    /**
     * Registra un intento fallido de autenticación
     * @param ipAddress Dirección IP del cliente
     * @param email Email del usuario (puede ser null)
     * @param attemptType Tipo de intento
     */
    void recordFailedAttempt(String ipAddress, String email, AttemptType attemptType);

    /**
     * Registra un intento exitoso de autenticación
     * @param ipAddress Dirección IP del cliente
     * @param email Email del usuario
     * @param attemptType Tipo de intento
     */
    void recordSuccessfulAttempt(String ipAddress, String email, AttemptType attemptType);

    /**
     * Verifica si una IP está bloqueada
     * @param ipAddress Dirección IP a verificar
     * @return true si está bloqueada, false si no
     */
    boolean isIpBlocked(String ipAddress);

    /**
     * Verifica si un usuario está bloqueado
     * @param email Email del usuario a verificar
     * @return true si está bloqueado, false si no
     */
    boolean isUserBlocked(String email);

    /**
     * Valida los límites de tasa antes de procesar una solicitud
     * @param ipAddress Dirección IP del cliente
     * @param email Email del usuario (puede ser null)
     * @param attemptType Tipo de intento
     * @throws com.figrclub.figrclubdb.exceptions.RateLimitExceededException si se excede el límite
     */
    void validateRateLimit(String ipAddress, String email, AttemptType attemptType);

    /**
     * Obtiene información detallada sobre el estado del rate limiting
     * @param ipAddress Dirección IP del cliente
     * @param email Email del usuario (puede ser null)
     * @return Información del rate limiting
     */
    RateLimitInfo getRateLimitInfo(String ipAddress, String email);

    /**
     * Limpia los intentos fallidos para un usuario después de un login exitoso
     * @param email Email del usuario
     */
    void clearFailedAttemptsForUser(String email);

    /**
     * Limpia los intentos fallidos para una IP
     * @param ipAddress Dirección IP
     */
    void clearFailedAttemptsForIp(String ipAddress);

    /**
     * Bloquea una IP explícitamente (acción manual)
     * @param ipAddress Dirección IP a bloquear
     * @param durationMinutes Duración del bloqueo en minutos
     * @param reason Razón del bloqueo
     */
    void blockIpExplicitly(String ipAddress, int durationMinutes, String reason);

    /**
     * Bloquea un usuario explícitamente (acción manual)
     * @param email Email del usuario a bloquear
     * @param durationMinutes Duración del bloqueo en minutos
     * @param reason Razón del bloqueo
     */
    void blockUserExplicitly(String email, int durationMinutes, String reason);

    /**
     * Desbloquea una IP (acción manual)
     * @param ipAddress Dirección IP a desbloquear
     */
    void unblockIp(String ipAddress);

    /**
     * Desbloquea un usuario (acción manual)
     * @param email Email del usuario a desbloquear
     */
    void unblockUser(String email);

    /**
     * Limpia registros antiguos de intentos de login (tarea programada)
     */
    void cleanupOldAttempts();

    /**
     * Obtiene intentos fallidos recientes para análisis
     * @param ipAddress Dirección IP (puede ser null)
     * @param email Email del usuario (puede ser null)
     * @param hours Número de horas hacia atrás
     * @return Lista de intentos fallidos
     */
    List<LoginAttempt> getRecentFailedAttempts(String ipAddress, String email, int hours);
}
