package com.figrclub.figrclubdb.domain.model;

import com.figrclub.figrclubdb.domain.base.Auditable;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Entidad para manejar tokens de verificación de email
 *
 * @author FigrClub Team
 * @version 1.0
 */
@Getter
@Setter
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "email_verification_tokens", indexes = {
        @Index(name = "idx_token", columnList = "token"),
        @Index(name = "idx_user_id", columnList = "user_id"),
        @Index(name = "idx_expiry_date", columnList = "expiry_date"),
        @Index(name = "idx_used_expiry", columnList = "used, expiry_date")
})
public class EmailVerificationToken extends Auditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "token", nullable = false, unique = true, length = 255)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, foreignKey = @ForeignKey(name = "fk_email_token_user"))
    private User user;

    @Column(name = "expiry_date", nullable = false)
    private LocalDateTime expiryDate;

    @Builder.Default
    @Column(name = "used", nullable = false)
    private boolean used = false;

    @Column(name = "used_at")
    private LocalDateTime usedAt;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    /**
     * Constructor para crear un nuevo token
     */
    public EmailVerificationToken(User user, String token, LocalDateTime expiryDate) {
        this.user = user;
        this.token = token;
        this.expiryDate = expiryDate;
        this.used = false;
    }

    /**
     * Verifica si el token ha expirado
     */
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryDate);
    }

    /**
     * Verifica si el token es válido (no usado y no expirado)
     */
    public boolean isValid() {
        return !used && !isExpired();
    }

    /**
     * Marca el token como usado
     */
    public void markAsUsed(String ipAddress, String userAgent) {
        this.used = true;
        this.usedAt = LocalDateTime.now();
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
    }
}
