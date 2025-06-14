package com.figrclub.figrclubdb.request;

import com.figrclub.figrclubdb.enums.ImageType;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request para la subida de imágenes de usuario
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ImageUploadRequest {

    /**
     * Tipo de imagen a subir (PROFILE o COVER)
     */
    @NotNull(message = "Image type is required")
    private ImageType imageType;

    /**
     * Texto alternativo para accesibilidad (opcional)
     */
    @Size(max = 500, message = "Alt text must not exceed 500 characters")
    private String altText;

    /**
     * Indica si se debe reemplazar la imagen existente del mismo tipo
     */
    @Builder.Default
    private Boolean replaceExisting = true;

    /**
     * Indica si se debe redimensionar automáticamente la imagen
     */
    @Builder.Default
    private Boolean autoResize = true;

    /**
     * Ancho máximo deseado (opcional, para redimensionamiento)
     */
    private Integer maxWidth;

    /**
     * Alto máximo deseado (opcional, para redimensionamiento)
     */
    private Integer maxHeight;

    /**
     * Calidad de compresión para imágenes JPEG (1-100)
     */
    @Builder.Default
    private Integer compressionQuality = 85;

    // ===== MÉTODOS DE VALIDACIÓN =====

    /**
     * Verifica si los parámetros de redimensionamiento son válidos
     */
    public boolean hasValidResizeParams() {
        if (maxWidth != null && maxWidth <= 0) return false;
        if (maxHeight != null && maxHeight <= 0) return false;
        return true;
    }

    /**
     * Verifica si la calidad de compresión es válida
     */
    public boolean hasValidCompressionQuality() {
        return compressionQuality != null &&
                compressionQuality >= 1 &&
                compressionQuality <= 100;
    }

    /**
     * Obtiene el ancho por defecto según el tipo de imagen
     */
    public Integer getDefaultMaxWidth() {
        if (maxWidth != null) return maxWidth;

        return switch (imageType) {
            case PROFILE -> 400;  // Imagen de perfil más pequeña
            case COVER -> 1200;   // Imagen de portada más grande
        };
    }

    /**
     * Obtiene el alto por defecto según el tipo de imagen
     */
    public Integer getDefaultMaxHeight() {
        if (maxHeight != null) return maxHeight;

        return switch (imageType) {
            case PROFILE -> 400;  // Imagen de perfil cuadrada
            case COVER -> 600;    // Imagen de portada con ratio 2:1
        };
    }

    /**
     * Valida el request completo
     */
    public boolean isValid() {
        return imageType != null &&
                hasValidResizeParams() &&
                hasValidCompressionQuality();
    }
}
