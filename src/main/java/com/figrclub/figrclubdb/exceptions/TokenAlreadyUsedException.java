package com.figrclub.figrclubdb.exceptions;

/**
 * Excepción para tokens ya utilizados
 */
public class TokenAlreadyUsedException extends RuntimeException {
  public TokenAlreadyUsedException(String message) {
    super(message);
  }

  public TokenAlreadyUsedException(String message, Throwable cause) {
    super(message, cause);
  }
}
