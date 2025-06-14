package com.figrclub.figrclubdb.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.figrclub.figrclubdb.enums.ImageType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * DTO para representar imágenes de usuario en las respuestas de la API
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserImageDto {

    private Long id;
    private Long userId;
    private ImageType imageType;
    private String originalFilename;
    private String publicUrl;
    private String contentType;
    private Long fileSize;
    private String formattedFileSize;
    private Integer width;
    private Integer height;
    private String dimensions;
    private Boolean isActive;
    private String altText;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createdAt;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime updatedAt;

    // ===== CAMPOS CALCULADOS =====

    /**
     * Indica si la imagen es de perfil
     */
    public boolean isProfileImage() {
        return imageType == ImageType.PROFILE;
    }

    /**
     * Indica si la imagen es de portada
     */
    public boolean isCoverImage() {
        return imageType == ImageType.COVER;
    }

    /**
     * Obtiene el nombre del tipo de imagen localizado
     */
    public String getImageTypeName() {
        return imageType != null ? imageType.getDisplayName() : null;
    }

    /**
     * Obtiene el nombre del tipo de imagen en español
     */
    public String getImageTypeNameEs() {
        return imageType != null ? imageType.getDisplayNameEs() : null;
    }

    // ===== MÉTODOS ESTÁTICOS PARA CREAR DTOs =====

    /**
     * Crea un DTO básico con solo información esencial
     */
    public static UserImageDto createBasic(Long id, ImageType imageType, String publicUrl) {
        return UserImageDto.builder()
                .id(id)
                .imageType(imageType)
                .publicUrl(publicUrl)
                .isActive(true)
                .build();
    }

    /**
     * Crea un DTO para respuesta de error
     */
    public static UserImageDto createError(String errorMessage) {
        return UserImageDto.builder()
                .altText(errorMessage)
                .isActive(false)
                .build();
    }
}
