package com.figrclub.figrclubdb.exceptions;

/**
 * Excepción para tokens expirados
 */
public class TokenExpiredException extends RuntimeException {
    public TokenExpiredException(String message) {
        super(message);
    }

    public TokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
