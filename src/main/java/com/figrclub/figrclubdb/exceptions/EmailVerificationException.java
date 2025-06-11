package com.figrclub.figrclubdb.exceptions;

/**
 * Excepción general para errores de verificación de email
 */
public class EmailVerificationException extends RuntimeException {
  public EmailVerificationException(String message) {
    super(message);
  }

  public EmailVerificationException(String message, Throwable cause) {
    super(message, cause);
  }
}
