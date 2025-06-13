package com.figrclub.figrclubdb.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.time.LocalDate;

/**
 * Request para actualizar información del usuario
 * NOTA: Los roles NO se pueden modificar a través de este request
 */
@Data
public class UserUpdateRequest {

    // ===== CAMPOS BÁSICOS =====

    @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
    private String firstName;

    @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
    private String lastName;

    @Email(message = "Please provide a valid email")
    private String email;

    // ===== CAMPOS DE CONTACTO =====

    @Size(max = 20, message = "Phone number cannot exceed 20 characters")
    private String phone;

    @Size(max = 100, message = "Country name cannot exceed 100 characters")
    private String country;

    @Size(max = 100, message = "City name cannot exceed 100 characters")
    private String city;

    private LocalDate birthDate;

    // ===== CAMPOS DE NEGOCIO (solo para vendedores profesionales) =====

    @Size(max = 200, message = "Business name cannot exceed 200 characters")
    private String businessName;

    @Size(max = 1000, message = "Business description cannot exceed 1000 characters")
    private String businessDescription;

    @Size(max = 500, message = "Business logo URL cannot exceed 500 characters")
    private String businessLogoUrl;

    @Size(max = 500, message = "Fiscal address cannot exceed 500 characters")
    private String fiscalAddress;

    @Size(max = 50, message = "Tax ID cannot exceed 50 characters")
    private String taxId;

    @Size(max = 100, message = "Payment method cannot exceed 100 characters")
    private String paymentMethod;

    // ===== CAMPOS ADICIONALES QUE PUEDEN SER ACTUALIZADOS =====

    /**
     * Password (solo si se quiere cambiar)
     */
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String password;

    /**
     * Estado habilitado/deshabilitado (solo para admins)
     */
    private Boolean enabled;

    // ===== NOTA IMPORTANTE =====

    /**
     * IMPORTANTE: Los roles NO se incluyen en este request porque son inmutables
     * No se puede modificar el rol de un usuario después de la creación de la cuenta
     */

    // Los siguientes campos NO están incluidos intencionalmente:
    // - role/roles: Los roles son inmutables
    // - userType: Se modifica solo a través de upgrade específicos
    // - subscriptionType: Se modifica solo a través de upgrade específicos
    // - emailVerifiedAt: Se modifica solo a través del proceso de verificación
}