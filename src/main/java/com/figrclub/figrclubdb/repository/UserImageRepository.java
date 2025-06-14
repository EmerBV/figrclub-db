package com.figrclub.figrclubdb.repository;

import com.figrclub.figrclubdb.domain.model.UserImage;
import com.figrclub.figrclubdb.enums.ImageType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repositorio para gestionar las imágenes de usuarios
 */
@Repository
public interface UserImageRepository extends JpaRepository<UserImage, Long> {

    // ===== MÉTODOS DE BÚSQUEDA POR USUARIO =====

    /**
     * Encuentra todas las imágenes de un usuario
     */
    List<UserImage> findByUserIdOrderByCreatedAtDesc(Long userId);

    /**
     * Encuentra todas las imágenes activas de un usuario
     */
    List<UserImage> findByUserIdAndIsActiveTrueOrderByCreatedAtDesc(Long userId);

    /**
     * Encuentra imágenes de un usuario con paginación
     */
    Page<UserImage> findByUserIdOrderByCreatedAtDesc(Long userId, Pageable pageable);

    // ===== MÉTODOS DE BÚSQUEDA POR TIPO =====

    /**
     * Encuentra imágenes de un usuario por tipo
     */
    List<UserImage> findByUserIdAndImageTypeOrderByCreatedAtDesc(Long userId, ImageType imageType);

    /**
     * Encuentra la imagen activa de un usuario por tipo
     */
    Optional<UserImage> findByUserIdAndImageTypeAndIsActiveTrue(Long userId, ImageType imageType);

    /**
     * Encuentra la imagen de perfil activa de un usuario
     */
    @Query("SELECT ui FROM UserImage ui WHERE ui.user.id = :userId AND ui.imageType = 'PROFILE' AND ui.isActive = true")
    Optional<UserImage> findActiveProfileImageByUserId(@Param("userId") Long userId);

    /**
     * Encuentra la imagen de portada activa de un usuario (solo PRO)
     */
    @Query("SELECT ui FROM UserImage ui WHERE ui.user.id = :userId AND ui.imageType = 'COVER' AND ui.isActive = true")
    Optional<UserImage> findActiveCoverImageByUserId(@Param("userId") Long userId);

    // ===== MÉTODOS DE GESTIÓN DE IMÁGENES ACTIVAS =====

    /**
     * Desactiva todas las imágenes de un tipo específico para un usuario
     */
    @Modifying
    @Query("UPDATE UserImage ui SET ui.isActive = false WHERE ui.user.id = :userId AND ui.imageType = :imageType")
    int deactivateUserImagesByType(@Param("userId") Long userId, @Param("imageType") ImageType imageType);

    /**
     * Desactiva todas las imágenes de un usuario
     */
    @Modifying
    @Query("UPDATE UserImage ui SET ui.isActive = false WHERE ui.user.id = :userId")
    int deactivateAllUserImages(@Param("userId") Long userId);

    // ===== MÉTODOS DE LIMPIEZA =====

    /**
     * Encuentra imágenes inactivas de un usuario
     */
    List<UserImage> findByUserIdAndIsActiveFalse(Long userId);

    /**
     * Elimina imágenes inactivas de un usuario
     */
    @Modifying
    @Query("DELETE FROM UserImage ui WHERE ui.user.id = :userId AND ui.isActive = false")
    int deleteInactiveUserImages(@Param("userId") Long userId);

    /**
     * Cuenta las imágenes de un usuario por tipo
     */
    long countByUserIdAndImageType(Long userId, ImageType imageType);

    /**
     * Cuenta las imágenes activas de un usuario
     */
    long countByUserIdAndIsActiveTrue(Long userId);

    // ===== MÉTODOS DE BÚSQUEDA GLOBAL =====

    /**
     * Encuentra todas las imágenes por tipo
     */
    Page<UserImage> findByImageTypeOrderByCreatedAtDesc(ImageType imageType, Pageable pageable);

    /**
     * Encuentra imágenes por nombre de archivo
     */
    @Query("SELECT ui FROM UserImage ui WHERE ui.storedFilename = :filename OR ui.originalFilename = :filename")
    List<UserImage> findByFilename(@Param("filename") String filename);

    /**
     * Verifica si existe una imagen con el nombre de archivo dado
     */
    boolean existsByStoredFilename(String storedFilename);

    // ===== MÉTODOS DE ESTADÍSTICAS =====

    /**
     * Cuenta el total de imágenes por tipo
     */
    @Query("SELECT COUNT(ui) FROM UserImage ui WHERE ui.imageType = :imageType")
    long countByImageType(@Param("imageType") ImageType imageType);

    /**
     * Cuenta usuarios con imagen de perfil
     */
    @Query("SELECT COUNT(DISTINCT ui.user.id) FROM UserImage ui WHERE ui.imageType = 'PROFILE' AND ui.isActive = true")
    long countUsersWithProfileImage();

    /**
     * Cuenta usuarios PRO con imagen de portada
     */
    @Query("SELECT COUNT(DISTINCT ui.user.id) FROM UserImage ui WHERE ui.imageType = 'COVER' AND ui.isActive = true")
    long countUsersWithCoverImage();

    /**
     * Calcula el tamaño total de imágenes de un usuario
     */
    @Query("SELECT COALESCE(SUM(ui.fileSize), 0) FROM UserImage ui WHERE ui.user.id = :userId AND ui.isActive = true")
    Long getTotalFileSizeByUserId(@Param("userId") Long userId);

    // ===== MÉTODOS DE ADMINISTRACIÓN =====

    /**
     * Encuentra imágenes sin usuario (huérfanas)
     */
    @Query("SELECT ui FROM UserImage ui WHERE ui.user IS NULL")
    List<UserImage> findOrphanedImages();

    /**
     * Encuentra imágenes de usuarios deshabilitados
     */
    @Query("SELECT ui FROM UserImage ui WHERE ui.user.isEnabled = false")
    Page<UserImage> findImagesOfDisabledUsers(Pageable pageable);
}
