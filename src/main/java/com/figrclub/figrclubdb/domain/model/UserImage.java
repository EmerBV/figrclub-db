package com.figrclub.figrclubdb.domain.model;

import com.figrclub.figrclubdb.domain.base.Auditable;
import com.figrclub.figrclubdb.enums.ImageType;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;

/**
 * Entidad que representa las imágenes de los usuarios
 * Incluye imagen de perfil (todos los usuarios) e imagen de portada (solo PRO)
 */
@Entity
@Table(name = "user_images", indexes = {
        @Index(name = "idx_user_images_user_id", columnList = "user_id"),
        @Index(name = "idx_user_images_type", columnList = "image_type"),
        @Index(name = "idx_user_images_user_type", columnList = "user_id, image_type"),
        @Index(name = "idx_user_images_active", columnList = "is_active")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserImage extends Auditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Usuario propietario de la imagen
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    @NotNull(message = "User is required")
    private User user;

    /**
     * Tipo de imagen (PROFILE o COVER)
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "image_type", nullable = false, length = 20)
    @NotNull(message = "Image type is required")
    private ImageType imageType;

    /**
     * Nombre original del archivo
     */
    @Column(name = "original_filename", nullable = false, length = 255)
    @NotBlank(message = "Original filename is required")
    @Size(max = 255, message = "Original filename must not exceed 255 characters")
    private String originalFilename;

    /**
     * Nombre del archivo guardado en el sistema
     */
    @Column(name = "stored_filename", nullable = false, length = 255)
    @NotBlank(message = "Stored filename is required")
    @Size(max = 255, message = "Stored filename must not exceed 255 characters")
    private String storedFilename;

    /**
     * Ruta completa del archivo
     */
    @Column(name = "file_path", nullable = false, length = 500)
    @NotBlank(message = "File path is required")
    @Size(max = 500, message = "File path must not exceed 500 characters")
    private String filePath;

    /**
     * URL pública para acceder a la imagen
     */
    @Column(name = "public_url", length = 500)
    @Size(max = 500, message = "Public URL must not exceed 500 characters")
    private String publicUrl;

    /**
     * Tipo MIME del archivo
     */
    @Column(name = "content_type", nullable = false, length = 100)
    @NotBlank(message = "Content type is required")
    @Size(max = 100, message = "Content type must not exceed 100 characters")
    private String contentType;

    /**
     * Tamaño del archivo en bytes
     */
    @Column(name = "file_size", nullable = false)
    @NotNull(message = "File size is required")
    private Long fileSize;

    /**
     * Ancho de la imagen en píxeles
     */
    @Column(name = "width")
    private Integer width;

    /**
     * Alto de la imagen en píxeles
     */
    @Column(name = "height")
    private Integer height;

    /**
     * Indica si esta imagen está activa/actualmente en uso
     */
    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private Boolean isActive = true;

    /**
     * Descripción alternativa para accesibilidad
     */
    @Column(name = "alt_text", length = 500)
    @Size(max = 500, message = "Alt text must not exceed 500 characters")
    private String altText;

    // ===== MÉTODOS DE CONVENIENCIA =====

    /**
     * Verifica si la imagen es de perfil
     */
    public boolean isProfileImage() {
        return imageType == ImageType.PROFILE;
    }

    /**
     * Verifica si la imagen es de portada
     */
    public boolean isCoverImage() {
        return imageType == ImageType.COVER;
    }

    /**
     * Obtiene la extensión del archivo
     */
    public String getFileExtension() {
        if (originalFilename != null && originalFilename.contains(".")) {
            return originalFilename.substring(originalFilename.lastIndexOf("."));
        }
        return "";
    }

    /**
     * Formatea el tamaño del archivo para mostrar
     */
    public String getFormattedFileSize() {
        if (fileSize == null) return "0 B";

        String[] units = {"B", "KB", "MB", "GB"};
        int unitIndex = 0;
        double size = fileSize.doubleValue();

        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }

        return String.format("%.1f %s", size, units[unitIndex]);
    }

    /**
     * Obtiene las dimensiones como string
     */
    public String getDimensions() {
        if (width != null && height != null) {
            return width + "x" + height;
        }
        return null;
    }

    /**
     * Verifica si la imagen tiene dimensiones válidas
     */
    public boolean hasValidDimensions() {
        return width != null && height != null && width > 0 && height > 0;
    }

    @Override
    public String toString() {
        return "UserImage{" +
                "id=" + id +
                ", userId=" + (user != null ? user.getId() : null) +
                ", imageType=" + imageType +
                ", originalFilename='" + originalFilename + '\'' +
                ", contentType='" + contentType + '\'' +
                ", fileSize=" + fileSize +
                ", isActive=" + isActive +
                '}';
    }
}
