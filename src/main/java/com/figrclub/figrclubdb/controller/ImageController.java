package com.figrclub.figrclubdb.controller;

import com.figrclub.figrclubdb.dto.UserImageDto;
import com.figrclub.figrclubdb.enums.ImageType;
import com.figrclub.figrclubdb.request.ImageUploadRequest;
import com.figrclub.figrclubdb.response.ApiResponse;
import com.figrclub.figrclubdb.service.image.IImageService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.springframework.http.HttpStatus.*;

/**
 * Controlador REST para la gestión de imágenes de usuario
 * Incluye endpoints para subir, gestionar y obtener imágenes de perfil y portada
 */
@RestController
@RequestMapping("${api.prefix}/images")
@RequiredArgsConstructor
@Tag(name = "Image Management", description = "User image management operations")
@Slf4j
public class ImageController {

    private final IImageService imageService;

    // ===== ENDPOINTS DE SUBIDA DE IMÁGENES =====

    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Upload user image", description = "Upload a profile or cover image for the current user")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> uploadImage(
            @RequestPart("file") MultipartFile file,
            @RequestPart("imageType") String imageType,
            @RequestPart(value = "altText", required = false) String altText,
            @RequestPart(value = "replaceExisting", required = false) String replaceExistingStr) {
        try {
            log.info("Uploading image of type: {}", imageType);

            // Convertir string a boolean con valor por defecto
            Boolean replaceExisting = replaceExistingStr != null ?
                    Boolean.parseBoolean(replaceExistingStr) : true;

            ImageUploadRequest request = ImageUploadRequest.builder()
                    .imageType(ImageType.fromString(imageType))
                    .altText(altText)
                    .replaceExisting(replaceExisting)
                    .autoResize(true)
                    .build();

            UserImageDto uploadedImage = imageService.uploadImage(file, request);

            Map<String, Object> response = new HashMap<>();
            response.put("image", uploadedImage);
            response.put("message", "Image uploaded successfully");

            return ResponseEntity.status(CREATED)
                    .body(new ApiResponse("Image uploaded successfully", response));

        } catch (Exception e) {
            log.error("Error uploading image: {}", e.getMessage());
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error uploading image: " + e.getMessage(), null));
        }
    }

    @PostMapping(value = "/profile", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Upload profile image", description = "Upload a profile image (available for all users)")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> uploadProfileImage(
            @RequestPart("file") MultipartFile file,
            @RequestPart(value = "altText", required = false) String altText) {
        try {
            log.info("Uploading profile image");

            UserImageDto uploadedImage = imageService.uploadProfileImage(file, altText);

            Map<String, Object> response = new HashMap<>();
            response.put("profileImage", uploadedImage);
            response.put("message", "Profile image uploaded successfully");

            return ResponseEntity.status(CREATED)
                    .body(new ApiResponse("Profile image uploaded successfully", response));

        } catch (Exception e) {
            log.error("Error uploading profile image: {}", e.getMessage());
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error uploading profile image: " + e.getMessage(), null));
        }
    }

    @PostMapping(value = "/cover", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Upload cover image", description = "Upload a cover image (only for PRO users)")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> uploadCoverImage(
            @RequestPart("file") MultipartFile file,
            @RequestPart(value = "altText", required = false) String altText) {
        try {
            log.info("Uploading cover image");

            UserImageDto uploadedImage = imageService.uploadCoverImage(file, altText);

            Map<String, Object> response = new HashMap<>();
            response.put("coverImage", uploadedImage);
            response.put("message", "Cover image uploaded successfully");

            return ResponseEntity.status(CREATED)
                    .body(new ApiResponse("Cover image uploaded successfully", response));

        } catch (Exception e) {
            log.error("Error uploading cover image: {}", e.getMessage());
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error uploading cover image: " + e.getMessage(), null));
        }
    }

    // ===== ENDPOINTS DE CONSULTA =====

    @GetMapping("/user/{userId}")
    @Operation(summary = "Get user images", description = "Get all images for a specific user")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> getUserImages(@PathVariable Long userId) {
        try {
            log.info("Fetching images for user: {}", userId);

            List<UserImageDto> images = imageService.getActiveUserImages(userId);

            Map<String, Object> response = new HashMap<>();
            response.put("images", images);
            response.put("totalImages", images.size());

            // Separar por tipo de imagen
            Map<String, UserImageDto> imagesByType = new HashMap<>();
            images.forEach(image -> {
                if (image.getImageType() == ImageType.PROFILE) {
                    imagesByType.put("profileImage", image);
                } else if (image.getImageType() == ImageType.COVER) {
                    imagesByType.put("coverImage", image);
                }
            });
            response.put("imagesByType", imagesByType);

            return ResponseEntity.ok(new ApiResponse("User images retrieved successfully", response));

        } catch (Exception e) {
            log.error("Error fetching user images: {}", e.getMessage());
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving user images", null));
        }
    }

    @GetMapping("/user/{userId}/paginated")
    @Operation(summary = "Get user images with pagination", description = "Get user images with pagination support")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> getUserImagesPaginated(
            @PathVariable Long userId,
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            log.info("Fetching paginated images for user: {}", userId);

            Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
            Page<UserImageDto> imagePage = imageService.getUserImages(userId, pageable);

            Map<String, Object> response = new HashMap<>();
            response.put("images", imagePage.getContent());
            response.put("currentPage", imagePage.getNumber());
            response.put("totalItems", imagePage.getTotalElements());
            response.put("totalPages", imagePage.getTotalPages());
            response.put("pageSize", imagePage.getSize());

            return ResponseEntity.ok(new ApiResponse("User images retrieved successfully", response));

        } catch (Exception e) {
            log.error("Error fetching paginated user images: {}", e.getMessage());
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving user images", null));
        }
    }

    @GetMapping("/user/{userId}/profile")
    @Operation(summary = "Get user profile image", description = "Get the active profile image for a user")
    public ResponseEntity<ApiResponse> getUserProfileImage(@PathVariable Long userId) {
        try {
            log.info("Fetching profile image for user: {}", userId);

            Optional<UserImageDto> profileImage = imageService.getActiveProfileImage(userId);

            if (profileImage.isPresent()) {
                Map<String, Object> response = new HashMap<>();
                response.put("profileImage", profileImage.get());

                return ResponseEntity.ok(new ApiResponse("Profile image retrieved successfully", response));
            } else {
                return ResponseEntity.status(NOT_FOUND)
                        .body(new ApiResponse("No profile image found for user", null));
            }

        } catch (Exception e) {
            log.error("Error fetching profile image: {}", e.getMessage());
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving profile image", null));
        }
    }

    @GetMapping("/user/{userId}/cover")
    @Operation(summary = "Get user cover image", description = "Get the active cover image for a user")
    public ResponseEntity<ApiResponse> getUserCoverImage(@PathVariable Long userId) {
        try {
            log.info("Fetching cover image for user: {}", userId);

            Optional<UserImageDto> coverImage = imageService.getActiveCoverImage(userId);

            if (coverImage.isPresent()) {
                Map<String, Object> response = new HashMap<>();
                response.put("coverImage", coverImage.get());

                return ResponseEntity.ok(new ApiResponse("Cover image retrieved successfully", response));
            } else {
                return ResponseEntity.status(NOT_FOUND)
                        .body(new ApiResponse("No cover image found for user", null));
            }

        } catch (Exception e) {
            log.error("Error fetching cover image: {}", e.getMessage());
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving cover image", null));
        }
    }

    @GetMapping("/{imageId}")
    @Operation(summary = "Get image by ID", description = "Get a specific image by its ID")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> getImageById(@PathVariable Long imageId) {
        try {
            log.info("Fetching image with ID: {}", imageId);

            UserImageDto image = imageService.getImageById(imageId);

            Map<String, Object> response = new HashMap<>();
            response.put("image", image);

            return ResponseEntity.ok(new ApiResponse("Image retrieved successfully", response));

        } catch (Exception e) {
            log.error("Error fetching image: {}", e.getMessage());
            return ResponseEntity.status(NOT_FOUND)
                    .body(new ApiResponse("Image not found: " + e.getMessage(), null));
        }
    }

    // ===== ENDPOINTS DE GESTIÓN =====

    @PutMapping("/{imageId}/alt-text")
    @Operation(summary = "Update image alt text", description = "Update the alt text of an image")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> updateImageAltText(
            @PathVariable Long imageId,
            @RequestBody Map<String, String> request) {
        try {
            String altText = request.get("altText");
            log.info("Updating alt text for image: {}", imageId);

            UserImageDto updatedImage = imageService.updateImageAltText(imageId, altText);

            Map<String, Object> response = new HashMap<>();
            response.put("image", updatedImage);

            return ResponseEntity.ok(new ApiResponse("Image alt text updated successfully", response));

        } catch (Exception e) {
            log.error("Error updating image alt text: {}", e.getMessage());
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error updating image alt text: " + e.getMessage(), null));
        }
    }

    @PostMapping("/{imageId}/activate")
    @Operation(summary = "Activate image", description = "Activate an image (deactivates others of the same type)")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> activateImage(@PathVariable Long imageId) {
        try {
            log.info("Activating image: {}", imageId);

            UserImageDto activatedImage = imageService.activateImage(imageId);

            Map<String, Object> response = new HashMap<>();
            response.put("image", activatedImage);

            return ResponseEntity.ok(new ApiResponse("Image activated successfully", response));

        } catch (Exception e) {
            log.error("Error activating image: {}", e.getMessage());
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error activating image: " + e.getMessage(), null));
        }
    }

    @PostMapping("/{imageId}/deactivate")
    @Operation(summary = "Deactivate image", description = "Deactivate an image")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> deactivateImage(@PathVariable Long imageId) {
        try {
            log.info("Deactivating image: {}", imageId);

            imageService.deactivateImage(imageId);

            return ResponseEntity.ok(new ApiResponse("Image deactivated successfully", null));

        } catch (Exception e) {
            log.error("Error deactivating image: {}", e.getMessage());
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error deactivating image: " + e.getMessage(), null));
        }
    }

    @DeleteMapping("/{imageId}")
    @Operation(summary = "Delete image", description = "Delete an image permanently")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> deleteImage(@PathVariable Long imageId) {
        try {
            log.info("Deleting image: {}", imageId);

            imageService.deleteImage(imageId);

            return ResponseEntity.ok(new ApiResponse("Image deleted successfully", null));

        } catch (Exception e) {
            log.error("Error deleting image: {}", e.getMessage());
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error deleting image: " + e.getMessage(), null));
        }
    }

    @DeleteMapping("/user/{userId}/type/{imageType}")
    @Operation(summary = "Delete user images by type", description = "Delete all images of a specific type for a user")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> deleteUserImagesByType(
            @PathVariable Long userId,
            @PathVariable String imageType) {
        try {
            ImageType type = ImageType.fromString(imageType);
            if (type == null) {
                return ResponseEntity.status(BAD_REQUEST)
                        .body(new ApiResponse("Invalid image type: " + imageType, null));
            }

            log.info("Deleting all {} images for user: {}", type, userId);

            imageService.deleteUserImagesByType(userId, type);

            return ResponseEntity.ok(new ApiResponse("Images deleted successfully", null));

        } catch (Exception e) {
            log.error("Error deleting user images: {}", e.getMessage());
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error deleting images: " + e.getMessage(), null));
        }
    }

    @DeleteMapping("/user/{userId}/inactive")
    @Operation(summary = "Delete inactive user images", description = "Delete all inactive images for a user")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> deleteInactiveUserImages(@PathVariable Long userId) {
        try {
            log.info("Deleting inactive images for user: {}", userId);

            imageService.deleteInactiveUserImages(userId);

            return ResponseEntity.ok(new ApiResponse("Inactive images deleted successfully", null));

        } catch (Exception e) {
            log.error("Error deleting inactive images: {}", e.getMessage());
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error deleting inactive images: " + e.getMessage(), null));
        }
    }

    // ===== ENDPOINTS DE INFORMACIÓN =====

    @GetMapping("/capabilities")
    @Operation(summary = "Get image capabilities", description = "Get information about image upload capabilities")
    public ResponseEntity<ApiResponse> getImageCapabilities() {
        try {
            Map<String, Object> capabilities = new HashMap<>();

            // Información sobre tipos de imagen
            Map<String, Object> imageTypes = new HashMap<>();
            imageTypes.put("PROFILE", Map.of(
                    "displayName", "Profile Image",
                    "displayNameEs", "Imagen de perfil",
                    "availableForAllUsers", true,
                    "maxSize", imageService.getMaxFileSize(ImageType.PROFILE),
                    "maxSizeMB", imageService.getMaxFileSize(ImageType.PROFILE) / (1024 * 1024)
            ));
            imageTypes.put("COVER", Map.of(
                    "displayName", "Cover Image",
                    "displayNameEs", "Imagen de portada",
                    "availableForAllUsers", false,
                    "requiresProSubscription", true,
                    "maxSize", imageService.getMaxFileSize(ImageType.COVER),
                    "maxSizeMB", imageService.getMaxFileSize(ImageType.COVER) / (1024 * 1024)
            ));

            capabilities.put("imageTypes", imageTypes);
            capabilities.put("allowedContentTypes", List.of("image/jpeg", "image/png", "image/webp"));
            capabilities.put("features", Map.of(
                    "autoResize", true,
                    "compression", true,
                    "altTextSupport", true,
                    "multipleImagesPerType", false
            ));

            return ResponseEntity.ok(new ApiResponse("Image capabilities retrieved successfully", capabilities));

        } catch (Exception e) {
            log.error("Error getting image capabilities: {}", e.getMessage());
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving capabilities", null));
        }
    }

    // ===== ENDPOINTS DE ADMINISTRACIÓN =====

    @GetMapping("/admin/statistics")
    @Operation(summary = "Get image statistics", description = "Get global image statistics (admin only)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getImageStatistics() {
        try {
            log.info("Fetching image statistics");

            Object statistics = imageService.getImageStatistics();

            return ResponseEntity.ok(new ApiResponse("Image statistics retrieved successfully", statistics));

        } catch (Exception e) {
            log.error("Error fetching image statistics: {}", e.getMessage());
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving statistics", null));
        }
    }

    @PostMapping("/admin/cleanup-orphaned")
    @Operation(summary = "Cleanup orphaned images", description = "Remove orphaned images from the system (admin only)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> cleanupOrphanedImages() {
        try {
            log.info("Starting orphaned images cleanup");

            int cleanedCount = imageService.cleanupOrphanedImages();

            Map<String, Object> response = new HashMap<>();
            response.put("cleanedImagesCount", cleanedCount);

            return ResponseEntity.ok(new ApiResponse("Orphaned images cleaned up successfully", response));

        } catch (Exception e) {
            log.error("Error cleaning up orphaned images: {}", e.getMessage());
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error during cleanup", null));
        }
    }

    @GetMapping("/admin/disabled-users")
    @Operation(summary = "Get images of disabled users", description = "Get images belonging to disabled users (admin only)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getImagesOfDisabledUsers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size) {
        try {
            log.info("Fetching images of disabled users");

            Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
            Page<UserImageDto> imagePage = imageService.getImagesOfDisabledUsers(pageable);

            Map<String, Object> response = new HashMap<>();
            response.put("images", imagePage.getContent());
            response.put("currentPage", imagePage.getNumber());
            response.put("totalItems", imagePage.getTotalElements());
            response.put("totalPages", imagePage.getTotalPages());
            response.put("pageSize", imagePage.getSize());

            return ResponseEntity.ok(new ApiResponse("Images of disabled users retrieved successfully", response));

        } catch (Exception e) {
            log.error("Error fetching images of disabled users: {}", e.getMessage());
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving images", null));
        }
    }

    // ===== ENDPOINTS ADMIN PARA GESTIÓN DE USUARIOS =====

    @PostMapping(value = "/admin/user/{userId}/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Upload image for user (admin)", description = "Upload an image for any user (admin only)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> uploadImageForUser(
            @PathVariable Long userId,
            @RequestPart("file") MultipartFile file,
            @RequestPart("imageType") String imageType,
            @RequestPart(value = "altText", required = false) String altText,
            @RequestPart(value = "replaceExisting", required = false) String replaceExistingStr) {
        try {
            log.info("Admin uploading {} image for user: {}", imageType, userId);

            // Convertir string a boolean con valor por defecto
            Boolean replaceExisting = replaceExistingStr != null ?
                    Boolean.parseBoolean(replaceExistingStr) : true;

            ImageUploadRequest request = ImageUploadRequest.builder()
                    .imageType(ImageType.fromString(imageType))
                    .altText(altText)
                    .replaceExisting(replaceExisting)
                    .autoResize(true)
                    .build();

            UserImageDto uploadedImage = imageService.uploadImageForUser(userId, file, request);

            Map<String, Object> response = new HashMap<>();
            response.put("image", uploadedImage);
            response.put("userId", userId);

            return ResponseEntity.status(CREATED)
                    .body(new ApiResponse("Image uploaded successfully for user", response));

        } catch (Exception e) {
            log.error("Error uploading image for user: {}", e.getMessage());
            return ResponseEntity.status(BAD_REQUEST)
                    .body(new ApiResponse("Error uploading image: " + e.getMessage(), null));
        }
    }
}
