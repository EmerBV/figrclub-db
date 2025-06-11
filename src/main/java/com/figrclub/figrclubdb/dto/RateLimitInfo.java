package com.figrclub.figrclubdb.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RateLimitInfo {

    private String ipAddress;
    private String email;

    private int ipAttempts;
    private int userAttempts;

    private int remainingIpAttempts;
    private int remainingUserAttempts;

    private int windowMinutes;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime ipBlockedUntil;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime userBlockedUntil;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime windowResetTime;

    private boolean ipBlocked;
    private boolean userBlocked;

    // Métodos de conveniencia
    public boolean isAnyBlocked() {
        return ipBlocked || userBlocked;
    }

    public int getMinRemainingAttempts() {
        return Math.min(remainingIpAttempts, remainingUserAttempts);
    }

    public LocalDateTime getEarliestUnblockTime() {
        if (ipBlockedUntil != null && userBlockedUntil != null) {
            return ipBlockedUntil.isAfter(userBlockedUntil) ? ipBlockedUntil : userBlockedUntil;
        }
        return ipBlockedUntil != null ? ipBlockedUntil : userBlockedUntil;
    }
}
