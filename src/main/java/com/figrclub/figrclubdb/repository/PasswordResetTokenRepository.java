package com.figrclub.figrclubdb.repository;

import com.figrclub.figrclubdb.domain.model.PasswordResetToken;
import com.figrclub.figrclubdb.domain.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    /**
     * Encuentra un token por su valor
     */
    Optional<PasswordResetToken> findByToken(String token);

    /**
     * Encuentra tokens válidos por usuario
     */
    @Query("SELECT prt FROM PasswordResetToken prt WHERE prt.user = :user " +
            "AND prt.used = false AND prt.expiresAt > :now")
    Optional<PasswordResetToken> findValidTokenByUser(@Param("user") User user, @Param("now") LocalDateTime now);

    /**
     * Encuentra todos los tokens del usuario
     */
    Optional<PasswordResetToken> findByUser(User user);

    /**
     * Invalida todos los tokens de un usuario
     */
    @Modifying
    @Query("UPDATE PasswordResetToken prt SET prt.used = true WHERE prt.user = :user")
    void invalidateAllUserTokens(@Param("user") User user);

    /**
     * Elimina tokens expirados
     */
    @Modifying
    @Query("DELETE FROM PasswordResetToken prt WHERE prt.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);

    /**
     * Cuenta tokens válidos por usuario
     */
    @Query("SELECT COUNT(prt) FROM PasswordResetToken prt WHERE prt.user = :user " +
            "AND prt.used = false AND prt.expiresAt > :now")
    long countValidTokensByUser(@Param("user") User user, @Param("now") LocalDateTime now);

    /**
     * Verifica si existe un token válido
     */
    @Query("SELECT CASE WHEN COUNT(prt) > 0 THEN true ELSE false END " +
            "FROM PasswordResetToken prt WHERE prt.token = :token " +
            "AND prt.used = false AND prt.expiresAt > :now")
    boolean existsByTokenAndValidState(@Param("token") String token, @Param("now") LocalDateTime now);
}
