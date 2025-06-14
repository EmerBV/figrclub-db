package com.figrclub.figrclubdb.exceptions;

/**
 * Excepción personalizada para errores relacionados con la gestión de imágenes
 */
public class ImageException extends RuntimeException {

    public ImageException(String message) {
        super(message);
    }

    public ImageException(String message, Throwable cause) {
        super(message, cause);
    }

    public ImageException(Throwable cause) {
        super(cause);
    }
}
