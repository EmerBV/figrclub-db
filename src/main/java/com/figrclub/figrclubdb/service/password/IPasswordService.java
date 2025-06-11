package com.figrclub.figrclubdb.service.password;

import com.figrclub.figrclubdb.request.PasswordChangeRequest;
import com.figrclub.figrclubdb.request.PasswordResetConfirmRequest;
import com.figrclub.figrclubdb.request.PasswordResetRequest;

public interface IPasswordService {

    /**
     * Cambia la contraseña del usuario autenticado
     * @param request Datos para el cambio de contraseña
     * //@throws PasswordException si la contraseña actual es incorrecta o las nuevas no coinciden
     */
    void changePassword(PasswordChangeRequest request);

    /**
     * Inicia el proceso de reset de contraseña enviando un email
     * @param request Email del usuario que solicita el reset
     * //@throws ResourceNotFoundException si el usuario no existe
     */
    void requestPasswordReset(PasswordResetRequest request);

    /**
     * Confirma el reset de contraseña con el token recibido
     * @param request Token y nueva contraseña
     * //@throws PasswordException si el token es inválido o expirado
     */
    void confirmPasswordReset(PasswordResetConfirmRequest request);

    /**
     * Valida que las contraseñas coincidan
     * @param password Contraseña
     * @param confirmPassword Confirmación de contraseña
     * //@throws PasswordException si no coinciden
     */
    void validatePasswordsMatch(String password, String confirmPassword);

    /**
     * Genera un token único para reset de contraseña
     * @return Token único
     */
    String generateResetToken();

    /**
     * Valida si un token de reset es válido
     * @param token Token a validar
     * @return true si es válido, false si no
     */
    boolean isValidResetToken(String token);

    /**
     * Limpia tokens expirados del sistema
     */
    void cleanupExpiredTokens();
}
