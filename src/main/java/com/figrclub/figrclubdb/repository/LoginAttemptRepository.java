package com.figrclub.figrclubdb.repository;

import com.figrclub.figrclubdb.domain.model.LoginAttempt;
import com.figrclub.figrclubdb.enums.AttemptType;
import com.figrclub.figrclubdb.enums.BlockType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

    // ===== CONSULTAS PARA CONTEO DE INTENTOS =====

    /**
     * Cuenta intentos fallidos por IP en una ventana de tiempo
     */
    @Query("SELECT COUNT(la) FROM LoginAttempt la WHERE " +
            "la.ipAddress = :ipAddress AND la.success = false AND " +
            "la.blocked = false AND la.attemptTime >= :since")
    long countFailedAttemptsByIp(@Param("ipAddress") String ipAddress,
                                 @Param("since") LocalDateTime since);

    /**
     * Cuenta intentos fallidos por usuario en una ventana de tiempo
     */
    @Query("SELECT COUNT(la) FROM LoginAttempt la WHERE " +
            "la.email = :email AND la.success = false AND " +
            "la.blocked = false AND la.attemptTime >= :since")
    long countFailedAttemptsByUser(@Param("email") String email,
                                   @Param("since") LocalDateTime since);

    /**
     * Cuenta intentos fallidos por IP y tipo de intento
     */
    @Query("SELECT COUNT(la) FROM LoginAttempt la WHERE " +
            "la.ipAddress = :ipAddress AND la.attemptType = :attemptType AND " +
            "la.success = false AND la.blocked = false AND la.attemptTime >= :since")
    long countFailedAttemptsByIpAndType(@Param("ipAddress") String ipAddress,
                                        @Param("attemptType") AttemptType attemptType,
                                        @Param("since") LocalDateTime since);

    /**
     * Cuenta intentos fallidos por usuario y tipo de intento
     */
    @Query("SELECT COUNT(la) FROM LoginAttempt la WHERE " +
            "la.email = :email AND la.attemptType = :attemptType AND " +
            "la.success = false AND la.blocked = false AND la.attemptTime >= :since")
    long countFailedAttemptsByUserAndType(@Param("email") String email,
                                          @Param("attemptType") AttemptType attemptType,
                                          @Param("since") LocalDateTime since);

    // ===== CONSULTAS PARA VERIFICACIÓN DE BLOQUEOS =====

    /**
     * Verifica si una IP está explícitamente bloqueada
     */
    @Query("SELECT CASE WHEN COUNT(la) > 0 THEN true ELSE false END FROM LoginAttempt la WHERE " +
            "la.ipAddress = :ipAddress AND la.blocked = true AND " +
            "la.blockedUntil > :now")
    boolean isIpExplicitlyBlocked(@Param("ipAddress") String ipAddress,
                                  @Param("now") LocalDateTime now);

    /**
     * Verifica si un usuario está explícitamente bloqueado
     */
    @Query("SELECT CASE WHEN COUNT(la) > 0 THEN true ELSE false END FROM LoginAttempt la WHERE " +
            "la.email = :email AND la.blocked = true AND " +
            "la.blockedUntil > :now")
    boolean isUserExplicitlyBlocked(@Param("email") String email,
                                    @Param("now") LocalDateTime now);

    /**
     * Obtiene el bloqueo activo más reciente para una IP
     */
    @Query("SELECT la FROM LoginAttempt la WHERE " +
            "la.ipAddress = :ipAddress AND la.blocked = true AND " +
            "la.blockedUntil > :now ORDER BY la.attemptTime DESC")
    Optional<LoginAttempt> findActiveBlockForIp(@Param("ipAddress") String ipAddress,
                                                @Param("now") LocalDateTime now);

    /**
     * Obtiene el bloqueo activo más reciente para un usuario
     */
    @Query("SELECT la FROM LoginAttempt la WHERE " +
            "la.email = :email AND la.blocked = true AND " +
            "la.blockedUntil > :now ORDER BY la.attemptTime DESC")
    Optional<LoginAttempt> findActiveBlockForUser(@Param("email") String email,
                                                  @Param("now") LocalDateTime now);

    // ===== CONSULTAS PARA BÚSQUEDA DE INTENTOS =====

    /**
     * Busca intentos fallidos por IP en un período
     */
    @Query("SELECT la FROM LoginAttempt la WHERE " +
            "la.ipAddress = :ipAddress AND la.success = false AND " +
            "la.attemptTime >= :since ORDER BY la.attemptTime DESC")
    List<LoginAttempt> findFailedAttemptsByIp(@Param("ipAddress") String ipAddress,
                                              @Param("since") LocalDateTime since);

    /**
     * Busca intentos fallidos por usuario en un período
     */
    @Query("SELECT la FROM LoginAttempt la WHERE " +
            "la.email = :email AND la.success = false AND " +
            "la.attemptTime >= :since ORDER BY la.attemptTime DESC")
    List<LoginAttempt> findFailedAttemptsByUser(@Param("email") String email,
                                                @Param("since") LocalDateTime since);

    /**
     * Busca intentos fallidos por usuario e IP en un período
     */
    @Query("SELECT la FROM LoginAttempt la WHERE " +
            "la.email = :email AND la.ipAddress = :ipAddress AND " +
            "la.success = false AND la.attemptTime >= :since ORDER BY la.attemptTime DESC")
    List<LoginAttempt> findFailedAttemptsByUserAndIp(@Param("email") String email,
                                                     @Param("ipAddress") String ipAddress,
                                                     @Param("since") LocalDateTime since);

    /**
     * Busca todos los intentos por IP con paginación
     */
    @Query("SELECT la FROM LoginAttempt la WHERE la.ipAddress = :ipAddress " +
            "ORDER BY la.attemptTime DESC")
    Page<LoginAttempt> findByIpAddress(@Param("ipAddress") String ipAddress, Pageable pageable);

    /**
     * Busca todos los intentos por usuario con paginación
     */
    @Query("SELECT la FROM LoginAttempt la WHERE la.email = :email " +
            "ORDER BY la.attemptTime DESC")
    Page<LoginAttempt> findByEmail(@Param("email") String email, Pageable pageable);

    /**
     * Busca intentos sospechosos (múltiples IPs para un usuario)
     */
    @Query("SELECT la FROM LoginAttempt la WHERE la.email = :email AND " +
            "la.attemptTime >= :since GROUP BY la.ipAddress HAVING COUNT(la.ipAddress) >= :threshold")
    List<LoginAttempt> findSuspiciousActivityByUser(@Param("email") String email,
                                                    @Param("since") LocalDateTime since,
                                                    @Param("threshold") int threshold);

    /**
     * Busca actividad sospechosa por IP (múltiples usuarios)
     */
    @Query("SELECT la FROM LoginAttempt la WHERE la.ipAddress = :ipAddress AND " +
            "la.attemptTime >= :since AND la.email IS NOT NULL " +
            "GROUP BY la.email HAVING COUNT(DISTINCT la.email) >= :threshold")
    List<LoginAttempt> findSuspiciousActivityByIp(@Param("ipAddress") String ipAddress,
                                                  @Param("since") LocalDateTime since,
                                                  @Param("threshold") int threshold);

    // ===== OPERACIONES DE LIMPIEZA Y MANTENIMIENTO =====

    /**
     * Limpia intentos fallidos para un usuario
     */
    @Modifying
    @Query("DELETE FROM LoginAttempt la WHERE la.email = :email AND " +
            "la.success = false AND la.blocked = false AND la.attemptTime >= :since")
    void clearFailedAttemptsForUser(@Param("email") String email,
                                    @Param("since") LocalDateTime since);

    /**
     * Limpia intentos fallidos para una IP
     */
    @Modifying
    @Query("DELETE FROM LoginAttempt la WHERE la.ipAddress = :ipAddress AND " +
            "la.success = false AND la.blocked = false AND la.attemptTime >= :since")
    void clearFailedAttemptsForIp(@Param("ipAddress") String ipAddress,
                                  @Param("since") LocalDateTime since);

    /**
     * Limpia bloqueos para una IP
     */
    @Modifying
    @Query("DELETE FROM LoginAttempt la WHERE la.ipAddress = :ipAddress AND la.blocked = true")
    void clearBlocksForIp(@Param("ipAddress") String ipAddress);

    /**
     * Limpia bloqueos para un usuario
     */
    @Modifying
    @Query("DELETE FROM LoginAttempt la WHERE la.email = :email AND la.blocked = true")
    void clearBlocksForUser(@Param("email") String email);

    /**
     * Elimina registros antiguos (limpieza programada)
     */
    @Modifying
    @Query("DELETE FROM LoginAttempt la WHERE la.attemptTime < :cutoff AND la.blocked = false")
    int deleteOldAttempts(@Param("cutoff") LocalDateTime cutoff);

    /**
     * Limpia bloqueos expirados
     */
    @Modifying
    @Query("DELETE FROM LoginAttempt la WHERE la.blocked = true AND la.blockedUntil < :now")
    int clearExpiredBlocks(@Param("now") LocalDateTime now);

    // ===== CONSULTAS ESTADÍSTICAS =====

    /**
     * Obtiene estadísticas de intentos por IP en las últimas horas
     */
    @Query("SELECT la.ipAddress, COUNT(la), SUM(CASE WHEN la.success = true THEN 1 ELSE 0 END), " +
            "SUM(CASE WHEN la.success = false THEN 1 ELSE 0 END) " +
            "FROM LoginAttempt la WHERE la.attemptTime >= :since " +
            "GROUP BY la.ipAddress ORDER BY COUNT(la) DESC")
    List<Object[]> getIpStatistics(@Param("since") LocalDateTime since);

    /**
     * Obtiene las IPs con más intentos fallidos
     */
    @Query("SELECT la.ipAddress, COUNT(la) as failedCount FROM LoginAttempt la WHERE " +
            "la.success = false AND la.attemptTime >= :since " +
            "GROUP BY la.ipAddress ORDER BY failedCount DESC")
    List<Object[]> getTopFailedIps(@Param("since") LocalDateTime since, Pageable pageable);

    /**
     * Obtiene usuarios con más intentos fallidos
     */
    @Query("SELECT la.email, COUNT(la) as failedCount FROM LoginAttempt la WHERE " +
            "la.success = false AND la.email IS NOT NULL AND la.attemptTime >= :since " +
            "GROUP BY la.email ORDER BY failedCount DESC")
    List<Object[]> getTopFailedUsers(@Param("since") LocalDateTime since, Pageable pageable);

    /**
     * Cuenta bloqueos activos por tipo
     */
    @Query("SELECT la.blockType, COUNT(la) FROM LoginAttempt la WHERE " +
            "la.blocked = true AND la.blockedUntil > :now " +
            "GROUP BY la.blockType")
    List<Object[]> getActiveBlocksByType(@Param("now") LocalDateTime now);

    /**
     * Obtiene actividad reciente con filtros
     */
    @Query("SELECT la FROM LoginAttempt la WHERE " +
            "(:ipAddress IS NULL OR la.ipAddress = :ipAddress) AND " +
            "(:email IS NULL OR la.email = :email) AND " +
            "(:attemptType IS NULL OR la.attemptType = :attemptType) AND " +
            "(:success IS NULL OR la.success = :success) AND " +
            "la.attemptTime >= :since ORDER BY la.attemptTime DESC")
    Page<LoginAttempt> findAttemptsWithFilters(@Param("ipAddress") String ipAddress,
                                               @Param("email") String email,
                                               @Param("attemptType") AttemptType attemptType,
                                               @Param("success") Boolean success,
                                               @Param("since") LocalDateTime since,
                                               Pageable pageable);

    /**
     * Busca patrones de ataque (mismo User-Agent desde múltiples IPs)
     */
    @Query("SELECT la.userAgent, COUNT(DISTINCT la.ipAddress) as ipCount, COUNT(la) as totalAttempts " +
            "FROM LoginAttempt la WHERE la.userAgent IS NOT NULL AND " +
            "la.success = false AND la.attemptTime >= :since " +
            "GROUP BY la.userAgent HAVING COUNT(DISTINCT la.ipAddress) >= :minIpCount " +
            "ORDER BY ipCount DESC, totalAttempts DESC")
    List<Object[]> findAttackPatterns(@Param("since") LocalDateTime since,
                                      @Param("minIpCount") int minIpCount);

    /**
     * Obtiene la última actividad exitosa de un usuario
     */
    @Query("SELECT la FROM LoginAttempt la WHERE la.email = :email AND " +
            "la.success = true ORDER BY la.attemptTime DESC")
    Optional<LoginAttempt> findLastSuccessfulAttempt(@Param("email") String email);

    /**
     * Obtiene estadísticas de intentos por hora del día
     */
    @Query("SELECT HOUR(la.attemptTime) as hour, COUNT(la) as attempts, " +
            "SUM(CASE WHEN la.success = false THEN 1 ELSE 0 END) as failed " +
            "FROM LoginAttempt la WHERE la.attemptTime >= :since " +
            "GROUP BY HOUR(la.attemptTime) ORDER BY hour")
    List<Object[]> getHourlyStatistics(@Param("since") LocalDateTime since);
}
