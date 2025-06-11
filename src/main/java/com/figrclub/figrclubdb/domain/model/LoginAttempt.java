package com.figrclub.figrclubdb.domain.model;

import com.figrclub.figrclubdb.enums.AttemptType;
import com.figrclub.figrclubdb.enums.BlockType;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "login_attempts", indexes = {
        @Index(name = "idx_ip_address", columnList = "ipAddress"),
        @Index(name = "idx_email", columnList = "email"),
        @Index(name = "idx_attempt_time", columnList = "attemptTime"),
        @Index(name = "idx_ip_time", columnList = "ipAddress, attemptTime"),
        @Index(name = "idx_email_time", columnList = "email, attemptTime"),
        @Index(name = "idx_blocked", columnList = "blocked, blockedUntil")
})
public class LoginAttempt {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address", nullable = false, length = 45) // IPv6 compatible
    private String ipAddress;

    @Column(length = 100)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(name = "attempt_type", nullable = false)
    private AttemptType attemptType;

    @Builder.Default
    @Column(nullable = false)
    private boolean success = false;

    @Column(name = "attempt_time", nullable = false)
    private LocalDateTime attemptTime;

    @Builder.Default
    @Column(nullable = false)
    private boolean blocked = false;

    @Enumerated(EnumType.STRING)
    @Column(name = "block_type")
    private BlockType blockType;

    @Column(name = "block_reason", length = 500)
    private String blockReason;

    @Column(name = "blocked_until")
    private LocalDateTime blockedUntil;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(name = "failure_reason", length = 200)
    private String failureReason;

    /**
     * Verifica si el bloqueo sigue activo
     */
    public boolean isBlockActive() {
        return blocked && blockedUntil != null && LocalDateTime.now().isBefore(blockedUntil);
    }

    /**
     * Verifica si el bloqueo ha expirado
     */
    public boolean isBlockExpired() {
        return blocked && blockedUntil != null && LocalDateTime.now().isAfter(blockedUntil);
    }
}
