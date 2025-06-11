package com.figrclub.figrclubdb.enums;

public enum BlockType {
    IP_BLOCKED,         // Bloqueo por IP
    USER_BLOCKED,       // Bloqueo por usuario
    SUSPICIOUS_ACTIVITY,// Actividad sospechosa
    MANUAL_BLOCK,       // Bloqueo manual por admin
    SECURITY_VIOLATION, // Violación de seguridad
    BRUTE_FORCE        // Ataque de fuerza bruta detectado
}
