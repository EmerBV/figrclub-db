package com.figrclub.figrclubdb.repository;

import com.figrclub.figrclubdb.domain.model.EmailVerificationToken;
import com.figrclub.figrclubdb.domain.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repositorio para tokens de verificación de email
 */
@Repository
public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {

    /**
     * Encuentra un token por su valor
     */
    Optional<EmailVerificationToken> findByToken(String token);

    /**
     * Encuentra un token válido por usuario
     */
    @Query("SELECT evt FROM EmailVerificationToken evt WHERE evt.user = :user AND evt.used = false AND evt.expiryDate > :now ORDER BY evt.createdAt DESC")
    Optional<EmailVerificationToken> findValidTokenByUser(@Param("user") User user, @Param("now") LocalDateTime now);

    /**
     * Encuentra todos los tokens válidos de un usuario
     */
    @Query("SELECT evt FROM EmailVerificationToken evt WHERE evt.user = :user AND evt.used = false AND evt.expiryDate > :now")
    List<EmailVerificationToken> findValidTokensByUser(@Param("user") User user, @Param("now") LocalDateTime now);

    /**
     * Cuenta tokens activos para un usuario
     */
    @Query("SELECT COUNT(evt) FROM EmailVerificationToken evt WHERE evt.user = :user AND evt.used = false AND evt.expiryDate > :now")
    long countActiveTokensByUser(@Param("user") User user, @Param("now") LocalDateTime now);

    /**
     * Encuentra tokens expirados
     */
    @Query("SELECT evt FROM EmailVerificationToken evt WHERE evt.expiryDate < :now")
    List<EmailVerificationToken> findExpiredTokens(@Param("now") LocalDateTime now);

    /**
     * Elimina tokens expirados
     */
    @Modifying
    @Query("DELETE FROM EmailVerificationToken evt WHERE evt.expiryDate < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);

    /**
     * Invalida todos los tokens de un usuario
     */
    @Modifying
    @Query("UPDATE EmailVerificationToken evt SET evt.used = true, evt.usedAt = :now WHERE evt.user = :user AND evt.used = false")
    void invalidateUserTokens(@Param("user") User user, @Param("now") LocalDateTime now);

    /**
     * Encuentra tokens por usuario
     */
    List<EmailVerificationToken> findByUserOrderByCreatedAtDesc(User user);

    /**
     * Verifica si existe un token válido para el usuario
     */
    @Query("SELECT CASE WHEN COUNT(evt) > 0 THEN true ELSE false END FROM EmailVerificationToken evt WHERE evt.user = :user AND evt.used = false AND evt.expiryDate > :now")
    boolean existsValidTokenForUser(@Param("user") User user, @Param("now") LocalDateTime now);

    /**
     * Encuentra el último token creado para un usuario
     */
    @Query("SELECT evt FROM EmailVerificationToken evt WHERE evt.user = :user ORDER BY evt.createdAt DESC LIMIT 1")
    Optional<EmailVerificationToken> findLatestTokenByUser(@Param("user") User user);
}
