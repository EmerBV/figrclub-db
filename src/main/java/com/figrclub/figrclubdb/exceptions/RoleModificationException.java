package com.figrclub.figrclubdb.exceptions;

/**
 * Excepción personalizada que se lanza cuando se intenta modificar un rol de usuario
 * Los roles son inmutables en el sistema y no pueden ser cambiados después de la creación
 */
public class RoleModificationException extends RuntimeException {

    public RoleModificationException(String message) {
        super(message);
    }

    public RoleModificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
