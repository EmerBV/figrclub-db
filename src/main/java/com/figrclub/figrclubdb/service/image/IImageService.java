package com.figrclub.figrclubdb.service.image;

import com.figrclub.figrclubdb.domain.model.UserImage;
import com.figrclub.figrclubdb.dto.UserImageDto;
import com.figrclub.figrclubdb.enums.ImageType;
import com.figrclub.figrclubdb.request.ImageUploadRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Optional;

/**
 * Interface del servicio de gestión de imágenes de usuario
 */
public interface IImageService {

    // ===== MÉTODOS DE SUBIDA DE IMÁGENES =====

    /**
     * Sube una imagen para el usuario autenticado
     */
    UserImageDto uploadImage(MultipartFile file, ImageUploadRequest request);

    /**
     * Sube una imagen para un usuario específico (solo admins)
     */
    @PreAuthorize("hasRole('ADMIN')")
    UserImageDto uploadImageForUser(Long userId, MultipartFile file, ImageUploadRequest request);

    /**
     * Sube una imagen de perfil (disponible para todos los usuarios)
     */
    UserImageDto uploadProfileImage(MultipartFile file, String altText);

    /**
     * Sube una imagen de portada (solo para usuarios PRO)
     */
    UserImageDto uploadCoverImage(MultipartFile file, String altText);

    /**
     * Sube una imagen de portada para un usuario específico (solo admins)
     */
    @PreAuthorize("hasRole('ADMIN')")
    UserImageDto uploadCoverImageForUser(Long userId, MultipartFile file, String altText);

    // ===== MÉTODOS DE CONSULTA =====

    /**
     * Obtiene todas las imágenes de un usuario
     */
    List<UserImageDto> getUserImages(Long userId);

    /**
     * Obtiene todas las imágenes activas de un usuario
     */
    List<UserImageDto> getActiveUserImages(Long userId);

    /**
     * Obtiene imágenes de un usuario con paginación
     */
    Page<UserImageDto> getUserImages(Long userId, Pageable pageable);

    /**
     * Obtiene la imagen activa de un usuario por tipo
     */
    Optional<UserImageDto> getActiveUserImage(Long userId, ImageType imageType);

    /**
     * Obtiene la imagen de perfil activa de un usuario
     */
    Optional<UserImageDto> getActiveProfileImage(Long userId);

    /**
     * Obtiene la imagen de portada activa de un usuario
     */
    Optional<UserImageDto> getActiveCoverImage(Long userId);

    /**
     * Obtiene una imagen por su ID
     */
    UserImageDto getImageById(Long imageId);

    // ===== MÉTODOS DE GESTIÓN =====

    /**
     * Actualiza el texto alternativo de una imagen
     */
    UserImageDto updateImageAltText(Long imageId, String altText);

    /**
     * Activa una imagen específica (desactiva las otras del mismo tipo)
     */
    UserImageDto activateImage(Long imageId);

    /**
     * Desactiva una imagen
     */
    void deactivateImage(Long imageId);

    /**
     * Elimina una imagen
     */
    void deleteImage(Long imageId);

    /**
     * Elimina todas las imágenes de un usuario de un tipo específico
     */
    void deleteUserImagesByType(Long userId, ImageType imageType);

    /**
     * Elimina todas las imágenes inactivas de un usuario
     */
    void deleteInactiveUserImages(Long userId);

    // ===== MÉTODOS DE VALIDACIÓN =====

    /**
     * Verifica si un usuario puede subir un tipo de imagen
     */
    boolean canUploadImageType(Long userId, ImageType imageType);

    /**
     * Verifica si un archivo es una imagen válida
     */
    boolean isValidImageFile(MultipartFile file);

    /**
     * Verifica si el tamaño del archivo es válido
     */
    boolean isValidFileSize(MultipartFile file, ImageType imageType);

    /**
     * Obtiene el tamaño máximo permitido para un tipo de imagen
     */
    long getMaxFileSize(ImageType imageType);

    // ===== MÉTODOS DE CONVERSIÓN =====

    /**
     * Convierte una entidad UserImage a DTO
     */
    UserImageDto convertToDto(UserImage userImage);

    /**
     * Convierte una lista de entidades a DTOs
     */
    List<UserImageDto> convertToDto(List<UserImage> userImages);

    // ===== MÉTODOS DE ADMINISTRACIÓN =====

    /**
     * Obtiene estadísticas de imágenes
     */
    @PreAuthorize("hasRole('ADMIN')")
    Object getImageStatistics();

    /**
     * Limpia imágenes huérfanas del sistema
     */
    @PreAuthorize("hasRole('ADMIN')")
    int cleanupOrphanedImages();

    /**
     * Obtiene imágenes de usuarios deshabilitados
     */
    @PreAuthorize("hasRole('ADMIN')")
    Page<UserImageDto> getImagesOfDisabledUsers(Pageable pageable);
}
