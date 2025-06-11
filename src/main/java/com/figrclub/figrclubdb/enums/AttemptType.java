package com.figrclub.figrclubdb.enums;

public enum AttemptType {
    LOGIN,              // Intento de login normal
    PASSWORD_RESET,     // Solicitud de reset de contraseña
    PASSWORD_CHANGE,    // Cambio de contraseña
    REGISTRATION,       // Registro de nuevo usuario
    EMAIL_VERIFICATION, // Verificación de email
    TWO_FACTOR_AUTH,    // Autenticación de dos factores
    API_ACCESS          // Acceso a API
}
