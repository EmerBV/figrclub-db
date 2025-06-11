package com.figrclub.figrclubdb.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

/**
 * DTO para representar un usuario en las respuestas de la API
 * Versión limpia sin métodos duplicados con Lombok
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDto {

    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String fullName;

    // Campos de estado del usuario
    private boolean enabled;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;

    // Campo de administrador
    private boolean admin;

    // Lista de roles
    private List<String> roles;

    // Campos de auditoría
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createdAt;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime updatedAt;

    private String createdBy;
    private String updatedBy;

    // Campos de verificación de email
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime emailVerifiedAt;

    // Campos adicionales para estadísticas
    private Long totalUsers; // Para estadísticas en respuestas de admin

    // Método adicional para verificación de email (NO duplica Lombok)
    @JsonProperty("emailVerified")
    public boolean isEmailVerified() {
        return emailVerifiedAt != null;
    }

    // Método adicional para estado de cuenta (NO duplica Lombok)
    @JsonProperty("accountStatus")
    public String getAccountStatus() {
        if (!enabled) {
            return "PENDING_VERIFICATION";
        } else if (!accountNonLocked) {
            return "LOCKED";
        } else if (!accountNonExpired) {
            return "EXPIRED";
        } else if (!credentialsNonExpired) {
            return "CREDENTIALS_EXPIRED";
        } else {
            return "ACTIVE";
        }
    }
}
