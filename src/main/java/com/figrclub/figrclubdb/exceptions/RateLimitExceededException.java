package com.figrclub.figrclubdb.exceptions;

import com.figrclub.figrclubdb.enums.BlockType;
import lombok.Getter;

@Getter
public class RateLimitExceededException extends RuntimeException {

    private final BlockType blockType;
    private final int blockDurationMinutes;
    private final String identifier; // IP o email bloqueado

    public RateLimitExceededException(String message, BlockType blockType, int blockDurationMinutes) {
        super(message);
        this.blockType = blockType;
        this.blockDurationMinutes = blockDurationMinutes;
        this.identifier = null;
    }

    public RateLimitExceededException(String message, BlockType blockType, int blockDurationMinutes, String identifier) {
        super(message);
        this.blockType = blockType;
        this.blockDurationMinutes = blockDurationMinutes;
        this.identifier = identifier;
    }

    public RateLimitExceededException(String message, BlockType blockType, int blockDurationMinutes, Throwable cause) {
        super(message, cause);
        this.blockType = blockType;
        this.blockDurationMinutes = blockDurationMinutes;
        this.identifier = null;
    }

    /**
     * Alias para compatibilidad - devuelve el tiempo de bloqueo en minutos
     * @return tiempo de bloqueo en minutos
     */
    public int getRetryAfterMinutes() {
        return blockDurationMinutes;
    }

    /**
     * Devuelve el tiempo de reintento en segundos para el header Retry-After
     * @return tiempo de reintento en segundos
     */
    public int getRetryAfterSeconds() {
        return blockDurationMinutes * 60;
    }
}
