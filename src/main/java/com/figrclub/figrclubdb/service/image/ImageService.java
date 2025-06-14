package com.figrclub.figrclubdb.service.image;

import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.domain.model.UserImage;
import com.figrclub.figrclubdb.dto.UserImageDto;
import com.figrclub.figrclubdb.enums.ImageType;
import com.figrclub.figrclubdb.enums.SubscriptionType;
import com.figrclub.figrclubdb.exceptions.ImageException;
import com.figrclub.figrclubdb.exceptions.ResourceNotFoundException;
import com.figrclub.figrclubdb.exceptions.UnauthorizedException;
import com.figrclub.figrclubdb.repository.UserImageRepository;
import com.figrclub.figrclubdb.request.ImageUploadRequest;
import com.figrclub.figrclubdb.service.user.IUserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Implementación del servicio de gestión de imágenes de usuario
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ImageService implements IImageService {

    private final UserImageRepository userImageRepository;
    private final IUserService userService;
    private final ModelMapper modelMapper;

    // ===== CONFIGURACIÓN DESDE APPLICATION.PROPERTIES =====

    @Value("${app.image.upload.path:uploads/images}")
    private String uploadPath;

    @Value("${app.image.base-url:http://localhost:8080/api/v1/images}")
    private String baseUrl;

    @Value("${app.image.max-size.profile:2097152}") // 2MB por defecto
    private long maxProfileImageSize;

    @Value("${app.image.max-size.cover:5242880}") // 5MB por defecto
    private long maxCoverImageSize;

    @Value("${app.image.allowed-types:image/jpeg,image/png,image/webp}")
    private String allowedContentTypes;

    // ===== MÉTODOS DE SUBIDA DE IMÁGENES =====

    @Override
    @Transactional
    public UserImageDto uploadImage(MultipartFile file, ImageUploadRequest request) {
        User currentUser = userService.getAuthenticatedUser();
        return uploadImageForUser(currentUser.getId(), file, request);
    }

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public UserImageDto uploadImageForUser(Long userId, MultipartFile file, ImageUploadRequest request) {
        log.info("Uploading {} image for user {}", request.getImageType(), userId);

        // Validaciones
        validateImageUpload(userId, file, request);

        // Obtener usuario
        User user = userService.getUserById(userId);

        // Desactivar imagen anterior si se debe reemplazar
        if (request.getReplaceExisting()) {
            deactivateUserImagesByType(userId, request.getImageType());
        }

        // Procesar y guardar imagen
        UserImage savedImage = processAndSaveImage(user, file, request);

        log.info("Successfully uploaded {} image with ID {} for user {}",
                request.getImageType(), savedImage.getId(), userId);

        return convertToDto(savedImage);
    }

    @Override
    @Transactional
    public UserImageDto uploadProfileImage(MultipartFile file, String altText) {
        ImageUploadRequest request = ImageUploadRequest.builder()
                .imageType(ImageType.PROFILE)
                .altText(altText)
                .replaceExisting(true)
                .autoResize(true)
                .build();

        return uploadImage(file, request);
    }

    @Override
    @Transactional
    public UserImageDto uploadCoverImage(MultipartFile file, String altText) {
        User currentUser = userService.getAuthenticatedUser();

        // Verificar que el usuario es PRO
        if (currentUser.getSubscriptionType() != SubscriptionType.PRO) {
            throw new UnauthorizedException("Cover images are only available for PRO users");
        }

        ImageUploadRequest request = ImageUploadRequest.builder()
                .imageType(ImageType.COVER)
                .altText(altText)
                .replaceExisting(true)
                .autoResize(true)
                .build();

        return uploadImage(file, request);
    }

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public UserImageDto uploadCoverImageForUser(Long userId, MultipartFile file, String altText) {
        ImageUploadRequest request = ImageUploadRequest.builder()
                .imageType(ImageType.COVER)
                .altText(altText)
                .replaceExisting(true)
                .autoResize(true)
                .build();

        return uploadImageForUser(userId, file, request);
    }

    // ===== MÉTODOS DE CONSULTA =====

    @Override
    public List<UserImageDto> getUserImages(Long userId) {
        List<UserImage> images = userImageRepository.findByUserIdOrderByCreatedAtDesc(userId);
        return convertToDto(images);
    }

    @Override
    public List<UserImageDto> getActiveUserImages(Long userId) {
        List<UserImage> images = userImageRepository.findByUserIdAndIsActiveTrueOrderByCreatedAtDesc(userId);
        return convertToDto(images);
    }

    @Override
    public Page<UserImageDto> getUserImages(Long userId, Pageable pageable) {
        Page<UserImage> imagePage = userImageRepository.findByUserIdOrderByCreatedAtDesc(userId, pageable);
        return imagePage.map(this::convertToDto);
    }

    @Override
    public Optional<UserImageDto> getActiveUserImage(Long userId, ImageType imageType) {
        Optional<UserImage> image = userImageRepository.findByUserIdAndImageTypeAndIsActiveTrue(userId, imageType);
        return image.map(this::convertToDto);
    }

    @Override
    public Optional<UserImageDto> getActiveProfileImage(Long userId) {
        Optional<UserImage> image = userImageRepository.findActiveProfileImageByUserId(userId);
        return image.map(this::convertToDto);
    }

    @Override
    public Optional<UserImageDto> getActiveCoverImage(Long userId) {
        Optional<UserImage> image = userImageRepository.findActiveCoverImageByUserId(userId);
        return image.map(this::convertToDto);
    }

    @Override
    public UserImageDto getImageById(Long imageId) {
        UserImage image = userImageRepository.findById(imageId)
                .orElseThrow(() -> new ResourceNotFoundException("Image not found with ID: " + imageId));
        return convertToDto(image);
    }

    // ===== MÉTODOS DE GESTIÓN =====

    @Override
    @Transactional
    public UserImageDto updateImageAltText(Long imageId, String altText) {
        UserImage image = userImageRepository.findById(imageId)
                .orElseThrow(() -> new ResourceNotFoundException("Image not found with ID: " + imageId));

        // Verificar permisos
        User currentUser = userService.getAuthenticatedUser();
        if (!image.getUser().getId().equals(currentUser.getId()) &&
                !currentUser.getRoleName().equals("ROLE_ADMIN")) {
            throw new UnauthorizedException("You can only update your own images");
        }

        image.setAltText(altText);
        UserImage savedImage = userImageRepository.save(image);

        log.info("Updated alt text for image {} of user {}", imageId, image.getUser().getId());
        return convertToDto(savedImage);
    }

    @Override
    @Transactional
    public UserImageDto activateImage(Long imageId) {
        UserImage image = userImageRepository.findById(imageId)
                .orElseThrow(() -> new ResourceNotFoundException("Image not found with ID: " + imageId));

        // Verificar permisos
        User currentUser = userService.getAuthenticatedUser();
        if (!image.getUser().getId().equals(currentUser.getId()) &&
                !currentUser.getRoleName().equals("ROLE_ADMIN")) {
            throw new UnauthorizedException("You can only manage your own images");
        }

        // Desactivar otras imágenes del mismo tipo
        userImageRepository.deactivateUserImagesByType(image.getUser().getId(), image.getImageType());

        // Activar esta imagen
        image.setIsActive(true);
        UserImage savedImage = userImageRepository.save(image);

        log.info("Activated image {} for user {}", imageId, image.getUser().getId());
        return convertToDto(savedImage);
    }

    @Override
    @Transactional
    public void deactivateImage(Long imageId) {
        UserImage image = userImageRepository.findById(imageId)
                .orElseThrow(() -> new ResourceNotFoundException("Image not found with ID: " + imageId));

        // Verificar permisos
        User currentUser = userService.getAuthenticatedUser();
        if (!image.getUser().getId().equals(currentUser.getId()) &&
                !currentUser.getRoleName().equals("ROLE_ADMIN")) {
            throw new UnauthorizedException("You can only manage your own images");
        }

        image.setIsActive(false);
        userImageRepository.save(image);

        log.info("Deactivated image {} for user {}", imageId, image.getUser().getId());
    }

    @Override
    @Transactional
    public void deleteImage(Long imageId) {
        UserImage image = userImageRepository.findById(imageId)
                .orElseThrow(() -> new ResourceNotFoundException("Image not found with ID: " + imageId));

        // Verificar permisos
        User currentUser = userService.getAuthenticatedUser();
        if (!image.getUser().getId().equals(currentUser.getId()) &&
                !currentUser.getRoleName().equals("ROLE_ADMIN")) {
            throw new UnauthorizedException("You can only delete your own images");
        }

        // Eliminar archivo físico
        deletePhysicalFile(image.getFilePath());

        // Eliminar registro de base de datos
        userImageRepository.delete(image);

        log.info("Deleted image {} for user {}", imageId, image.getUser().getId());
    }

    @Override
    @Transactional
    public void deleteUserImagesByType(Long userId, ImageType imageType) {
        User currentUser = userService.getAuthenticatedUser();
        if (!userId.equals(currentUser.getId()) &&
                !currentUser.getRoleName().equals("ROLE_ADMIN")) {
            throw new UnauthorizedException("You can only delete your own images");
        }

        List<UserImage> images = userImageRepository.findByUserIdAndImageTypeOrderByCreatedAtDesc(userId, imageType);

        for (UserImage image : images) {
            deletePhysicalFile(image.getFilePath());
            userImageRepository.delete(image);
        }

        log.info("Deleted all {} images for user {}", imageType, userId);
    }

    @Override
    @Transactional
    public void deleteInactiveUserImages(Long userId) {
        User currentUser = userService.getAuthenticatedUser();
        if (!userId.equals(currentUser.getId()) &&
                !currentUser.getRoleName().equals("ROLE_ADMIN")) {
            throw new UnauthorizedException("You can only delete your own images");
        }

        List<UserImage> inactiveImages = userImageRepository.findByUserIdAndIsActiveFalse(userId);

        for (UserImage image : inactiveImages) {
            deletePhysicalFile(image.getFilePath());
        }

        int deletedCount = userImageRepository.deleteInactiveUserImages(userId);
        log.info("Deleted {} inactive images for user {}", deletedCount, userId);
    }

    // ===== MÉTODOS DE VALIDACIÓN =====

    @Override
    public boolean canUploadImageType(Long userId, ImageType imageType) {
        if (imageType == ImageType.PROFILE) {
            return true; // Todos los usuarios pueden subir imágenes de perfil
        }

        if (imageType == ImageType.COVER) {
            User user = userService.getUserById(userId);
            return user.getSubscriptionType() == SubscriptionType.PRO;
        }

        return false;
    }

    @Override
    public boolean isValidImageFile(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            return false;
        }

        String contentType = file.getContentType();
        if (contentType == null) {
            return false;
        }

        List<String> allowedTypes = Arrays.asList(allowedContentTypes.split(","));
        return allowedTypes.contains(contentType.toLowerCase());
    }

    @Override
    public boolean isValidFileSize(MultipartFile file, ImageType imageType) {
        if (file == null) return false;

        long maxSize = getMaxFileSize(imageType);
        return file.getSize() <= maxSize;
    }

    @Override
    public long getMaxFileSize(ImageType imageType) {
        return imageType == ImageType.PROFILE ? maxProfileImageSize : maxCoverImageSize;
    }

    // ===== MÉTODOS DE CONVERSIÓN =====

    @Override
    public UserImageDto convertToDto(UserImage userImage) {
        UserImageDto dto = modelMapper.map(userImage, UserImageDto.class);
        dto.setUserId(userImage.getUser().getId());
        dto.setFormattedFileSize(userImage.getFormattedFileSize());
        dto.setDimensions(userImage.getDimensions());
        return dto;
    }

    @Override
    public List<UserImageDto> convertToDto(List<UserImage> userImages) {
        return userImages.stream()
                .map(this::convertToDto)
                .toList();
    }

    // ===== MÉTODOS PRIVADOS DE UTILIDAD =====

    private void validateImageUpload(Long userId, MultipartFile file, ImageUploadRequest request) {
        // Validar archivo
        if (file == null || file.isEmpty()) {
            throw new ImageException("File is required");
        }

        // Validar tipo de imagen
        if (!isValidImageFile(file)) {
            throw new ImageException("Invalid image format. Allowed: " + allowedContentTypes);
        }

        // Validar tamaño
        if (!isValidFileSize(file, request.getImageType())) {
            throw new ImageException("File size exceeds limit of " +
                    getMaxFileSize(request.getImageType()) / (1024 * 1024) + "MB");
        }

        // Validar permisos para el tipo de imagen
        if (!canUploadImageType(userId, request.getImageType())) {
            throw new UnauthorizedException("You don't have permission to upload " +
                    request.getImageType() + " images");
        }

        // Validar request
        if (!request.isValid()) {
            throw new ImageException("Invalid upload request parameters");
        }
    }

    private UserImage processAndSaveImage(User user, MultipartFile file, ImageUploadRequest request) {
        try {
            // Crear directorio si no existe
            Path uploadDir = Paths.get(uploadPath);
            if (!Files.exists(uploadDir)) {
                Files.createDirectories(uploadDir);
            }

            // Generar nombre único para el archivo
            String originalFilename = file.getOriginalFilename();
            String extension = originalFilename != null && originalFilename.contains(".") ?
                    originalFilename.substring(originalFilename.lastIndexOf(".")) : ".jpg";
            String storedFilename = generateUniqueFilename(user.getId(), request.getImageType(), extension);

            // Ruta completa del archivo
            Path filePath = uploadDir.resolve(storedFilename);

            // Procesar imagen (redimensionar si es necesario)
            byte[] processedImageData = processImage(file, request);

            // Guardar archivo
            Files.write(filePath, processedImageData);

            // Obtener dimensiones de la imagen procesada
            BufferedImage bufferedImage = ImageIO.read(new ByteArrayInputStream(processedImageData));

            // Crear entidad UserImage
            UserImage userImage = UserImage.builder()
                    .user(user)
                    .imageType(request.getImageType())
                    .originalFilename(originalFilename)
                    .storedFilename(storedFilename)
                    .filePath(filePath.toString())
                    .publicUrl(baseUrl + "/" + storedFilename)
                    .contentType(file.getContentType())
                    .fileSize((long) processedImageData.length)
                    .width(bufferedImage.getWidth())
                    .height(bufferedImage.getHeight())
                    .isActive(true)
                    .altText(request.getAltText())
                    .build();

            return userImageRepository.save(userImage);

        } catch (IOException e) {
            log.error("Error processing image for user {}: {}", user.getId(), e.getMessage());
            throw new ImageException("Error processing image: " + e.getMessage());
        }
    }

    private byte[] processImage(MultipartFile file, ImageUploadRequest request) throws IOException {
        BufferedImage originalImage = ImageIO.read(file.getInputStream());

        if (originalImage == null) {
            throw new ImageException("Unable to read image file");
        }

        BufferedImage processedImage = originalImage;

        // Redimensionar si es necesario
        if (request.getAutoResize()) {
            int maxWidth = request.getDefaultMaxWidth();
            int maxHeight = request.getDefaultMaxHeight();

            if (originalImage.getWidth() > maxWidth || originalImage.getHeight() > maxHeight) {
                processedImage = resizeImage(originalImage, maxWidth, maxHeight);
            }
        }

        // Convertir a bytes
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        String formatName = getImageFormat(file.getContentType());
        ImageIO.write(processedImage, formatName, baos);

        return baos.toByteArray();
    }

    private BufferedImage resizeImage(BufferedImage originalImage, int maxWidth, int maxHeight) {
        int originalWidth = originalImage.getWidth();
        int originalHeight = originalImage.getHeight();

        // Calcular nuevas dimensiones manteniendo la proporción
        double widthRatio = (double) maxWidth / originalWidth;
        double heightRatio = (double) maxHeight / originalHeight;
        double ratio = Math.min(widthRatio, heightRatio);

        int newWidth = (int) (originalWidth * ratio);
        int newHeight = (int) (originalHeight * ratio);

        // Crear imagen redimensionada
        BufferedImage resizedImage = new BufferedImage(newWidth, newHeight, BufferedImage.TYPE_INT_RGB);
        Graphics2D g2d = resizedImage.createGraphics();

        // Configurar rendering de alta calidad
        g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
        g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        g2d.drawImage(originalImage, 0, 0, newWidth, newHeight, null);
        g2d.dispose();

        return resizedImage;
    }

    private String generateUniqueFilename(Long userId, ImageType imageType, String extension) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        String uuid = UUID.randomUUID().toString().substring(0, 8);
        return String.format("user_%d_%s_%s_%s%s", userId, imageType.name().toLowerCase(), timestamp, uuid, extension);
    }

    private String getImageFormat(String contentType) {
        return switch (contentType.toLowerCase()) {
            case "image/png" -> "png";
            case "image/webp" -> "webp";
            default -> "jpg";
        };
    }

    private void deletePhysicalFile(String filePath) {
        try {
            Path path = Paths.get(filePath);
            if (Files.exists(path)) {
                Files.delete(path);
                log.debug("Deleted physical file: {}", filePath);
            }
        } catch (IOException e) {
            log.warn("Failed to delete physical file {}: {}", filePath, e.getMessage());
        }
    }

    private void deactivateUserImagesByType(Long userId, ImageType imageType) {
        int deactivatedCount = userImageRepository.deactivateUserImagesByType(userId, imageType);
        if (deactivatedCount > 0) {
            log.debug("Deactivated {} existing {} images for user {}", deactivatedCount, imageType, userId);
        }
    }

    // ===== MÉTODOS DE ADMINISTRACIÓN =====

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public Object getImageStatistics() {
        Map<String, Object> stats = new HashMap<>();

        stats.put("totalImages", userImageRepository.count());
        stats.put("profileImages", userImageRepository.countByImageType(ImageType.PROFILE));
        stats.put("coverImages", userImageRepository.countByImageType(ImageType.COVER));
        stats.put("usersWithProfileImage", userImageRepository.countUsersWithProfileImage());
        stats.put("usersWithCoverImage", userImageRepository.countUsersWithCoverImage());

        return stats;
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public int cleanupOrphanedImages() {
        List<UserImage> orphanedImages = userImageRepository.findOrphanedImages();

        for (UserImage image : orphanedImages) {
            deletePhysicalFile(image.getFilePath());
            userImageRepository.delete(image);
        }

        log.info("Cleaned up {} orphaned images", orphanedImages.size());
        return orphanedImages.size();
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public Page<UserImageDto> getImagesOfDisabledUsers(Pageable pageable) {
        Page<UserImage> imagePage = userImageRepository.findImagesOfDisabledUsers(pageable);
        return imagePage.map(this::convertToDto);
    }
}
