package com.figrclub.figrclubdb.enums;

/**
 * Enum que define los tipos de imágenes que pueden tener los usuarios
 */
public enum ImageType {
    /**
     * Imagen de perfil - Disponible para todos los usuarios
     */
    PROFILE("Profile Image", "Imagen de perfil", true),

    /**
     * Imagen de portada - Solo disponible para usuarios PRO
     */
    COVER("Cover Image", "Imagen de portada", false);

    private final String displayName;
    private final String displayNameEs;
    private final boolean availableForAllUsers;

    ImageType(String displayName, String displayNameEs, boolean availableForAllUsers) {
        this.displayName = displayName;
        this.displayNameEs = displayNameEs;
        this.availableForAllUsers = availableForAllUsers;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDisplayNameEs() {
        return displayNameEs;
    }

    public boolean isAvailableForAllUsers() {
        return availableForAllUsers;
    }

    /**
     * Verifica si el tipo de imagen requiere suscripción PRO
     */
    public boolean requiresProSubscription() {
        return !availableForAllUsers;
    }

    /**
     * Obtiene el tipo de imagen desde un string ignorando mayúsculas/minúsculas
     */
    public static ImageType fromString(String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }

        try {
            return ImageType.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Verifica si un string es un tipo de imagen válido
     */
    public static boolean isValid(String value) {
        return fromString(value) != null;
    }
}
