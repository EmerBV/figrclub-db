package com.figrclub.figrclubdb.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Configuración para el manejo de imágenes y archivos estáticos
 */
@Configuration
@Slf4j
public class ImageConfig implements WebMvcConfigurer {

    @Value("${app.image.upload.path:uploads/images}")
    private String uploadPath;

    /**
     * Inicialización: crear directorio de imágenes si no existe
     */
    @PostConstruct
    public void init() {
        try {
            Path uploadDir = Paths.get(uploadPath);
            if (!Files.exists(uploadDir)) {
                Files.createDirectories(uploadDir);
                log.info("Created image upload directory: {}", uploadDir.toAbsolutePath());
            } else {
                log.info("Image upload directory exists: {}", uploadDir.toAbsolutePath());
            }
        } catch (IOException e) {
            log.error("Failed to create image upload directory: {}", e.getMessage());
            throw new RuntimeException("Could not create upload directory", e);
        }
    }

    /**
     * Configurar manejo de recursos estáticos para servir imágenes
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Servir imágenes desde el directorio de uploads
        registry.addResourceHandler("/api/v1/images/**")
                .addResourceLocations("file:" + uploadPath + "/")
                .setCachePeriod(3600); // Cache por 1 hora

        log.info("Configured static resource handler for images: /api/v1/images/** -> file:{}/", uploadPath);
    }
}
