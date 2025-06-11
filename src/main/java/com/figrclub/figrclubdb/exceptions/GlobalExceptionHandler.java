package com.figrclub.figrclubdb.exceptions;

import com.figrclub.figrclubdb.exceptions.*;
import com.figrclub.figrclubdb.response.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Manejador global de excepciones actualizado con soporte para verificación de email
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /**
     * Maneja excepciones de recursos no encontrados
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse> handleResourceNotFound(ResourceNotFoundException e, WebRequest request) {
        log.warn("Resource not found: {} - URI: {}", e.getMessage(), request.getDescription(false));
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ApiResponse(e.getMessage(), null));
    }

    /**
     * Maneja excepciones de recursos que ya existen
     */
    @ExceptionHandler(AlreadyExistsException.class)
    public ResponseEntity<ApiResponse> handleAlreadyExists(AlreadyExistsException e, WebRequest request) {
        log.warn("Resource already exists: {} - URI: {}", e.getMessage(), request.getDescription(false));
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ApiResponse(e.getMessage(), null));
    }

    /**
     * Maneja excepciones de tokens expirados
     */
    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<ApiResponse> handleTokenExpired(TokenExpiredException e, WebRequest request) {
        log.warn("Token expired: {} - URI: {}", e.getMessage(), request.getDescription(false));
        return ResponseEntity.status(HttpStatus.GONE)
                .body(new ApiResponse(e.getMessage(), createTokenErrorDetails("EXPIRED")));
    }

    /**
     * Maneja excepciones de tokens ya utilizados
     */
    @ExceptionHandler(TokenAlreadyUsedException.class)
    public ResponseEntity<ApiResponse> handleTokenAlreadyUsed(TokenAlreadyUsedException e, WebRequest request) {
        log.warn("Token already used: {} - URI: {}", e.getMessage(), request.getDescription(false));
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ApiResponse(e.getMessage(), createTokenErrorDetails("ALREADY_USED")));
    }

    /**
     * Maneja excepciones generales de verificación de email
     */
    @ExceptionHandler(EmailVerificationException.class)
    public ResponseEntity<ApiResponse> handleEmailVerification(EmailVerificationException e, WebRequest request) {
        log.error("Email verification error: {} - URI: {}", e.getMessage(), request.getDescription(false));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse(e.getMessage(), null));
    }

    /**
     * Maneja errores de validación de campos
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse> handleValidationErrors(MethodArgumentNotValidException e) {
        log.warn("Validation error: {}", e.getMessage());

        Map<String, String> errors = new HashMap<>();
        e.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse("Errores de validación", errors));
    }

    /**
     * Maneja errores de validación de constraintos
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiResponse> handleConstraintViolation(ConstraintViolationException e) {
        log.warn("Constraint violation: {}", e.getMessage());

        Map<String, String> errors = e.getConstraintViolations()
                .stream()
                .collect(Collectors.toMap(
                        violation -> violation.getPropertyPath().toString(),
                        ConstraintViolation::getMessage
                ));

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse("Errores de validación", errors));
    }

    /**
     * Maneja parámetros faltantes en requests
     */
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ApiResponse> handleMissingParameter(MissingServletRequestParameterException e) {
        log.warn("Missing parameter: {}", e.getMessage());

        String message = String.format("Parámetro requerido '%s' de tipo '%s' no está presente",
                e.getParameterName(), e.getParameterType());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse(message, null));
    }

    /**
     * Maneja errores de tipo de argumentos
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiResponse> handleTypeMismatch(MethodArgumentTypeMismatchException e) {
        log.warn("Type mismatch: {}", e.getMessage());

        String message = String.format("Parámetro '%s' debe ser de tipo '%s'",
                e.getName(), e.getRequiredType() != null ? e.getRequiredType().getSimpleName() : "unknown");

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse(message, null));
    }

    /**
     * Maneja errores de autenticación
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse> handleAuthentication(AuthenticationException e, WebRequest request) {
        log.warn("Authentication error: {} - URI: {}", e.getMessage(), request.getDescription(false));
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiResponse("Error de autenticación", null));
    }

    /**
     * Maneja errores de credenciales incorrectas
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse> handleBadCredentials(BadCredentialsException e, WebRequest request) {
        log.warn("Bad credentials: {} - URI: {}", e.getMessage(), request.getDescription(false));
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiResponse("Email o contraseña incorrectos", null));
    }

    /**
     * Maneja errores de cuenta deshabilitada
     */
    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<ApiResponse> handleDisabled(DisabledException e, WebRequest request) {
        log.warn("Account disabled: {} - URI: {}", e.getMessage(), request.getDescription(false));
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ApiResponse("Cuenta deshabilitada. Verifica tu email para activarla.",
                        createAccountErrorDetails("DISABLED")));
    }

    /**
     * Maneja errores de acceso denegado
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse> handleAccessDenied(AccessDeniedException e, WebRequest request) {
        log.warn("Access denied: {} - URI: {}", e.getMessage(), request.getDescription(false));
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ApiResponse("Acceso denegado", null));
    }

    /**
     * Maneja excepciones de runtime generales
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse> handleRuntimeException(RuntimeException e, WebRequest request) {
        log.error("Runtime error: {} - URI: {}", e.getMessage(), request.getDescription(false), e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiResponse("Error interno del servidor", null));
    }

    /**
     * Maneja todas las demás excepciones
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse> handleGeneralException(Exception e, WebRequest request) {
        log.error("Unexpected error: {} - URI: {}", e.getMessage(), request.getDescription(false), e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiResponse("Error interno del servidor", null));
    }

    /**
     * Crea detalles de error para tokens
     */
    private Map<String, Object> createTokenErrorDetails(String errorType) {
        Map<String, Object> details = new HashMap<>();
        details.put("errorType", errorType);
        details.put("timestamp", java.time.LocalDateTime.now());

        switch (errorType) {
            case "EXPIRED":
                details.put("action", "REQUEST_NEW_TOKEN");
                details.put("message", "Solicita un nuevo token de verificación");
                break;
            case "ALREADY_USED":
                details.put("action", "CHECK_EMAIL_STATUS");
                details.put("message", "Verifica el estado de tu email");
                break;
            default:
                details.put("action", "CONTACT_SUPPORT");
                break;
        }

        return details;
    }

    /**
     * Crea detalles de error para cuentas
     */
    private Map<String, Object> createAccountErrorDetails(String errorType) {
        Map<String, Object> details = new HashMap<>();
        details.put("errorType", errorType);
        details.put("timestamp", java.time.LocalDateTime.now());

        if ("DISABLED".equals(errorType)) {
            details.put("action", "VERIFY_EMAIL");
            details.put("message", "Verifica tu email para activar la cuenta");
        }

        return details;
    }
}
