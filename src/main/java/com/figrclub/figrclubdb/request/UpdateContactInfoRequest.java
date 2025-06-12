package com.figrclub.figrclubdb.request;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Request para actualizar información de contacto adicional
 */
@Data
public class UpdateContactInfoRequest {

    @Pattern(regexp = "^[+]?[0-9\\s\\-\\(\\)]{7,20}$",
            message = "Phone number format is invalid")
    private String phone;

    @Size(min = 2, max = 100, message = "Country must be between 2 and 100 characters")
    private String country;

    @Size(min = 2, max = 100, message = "City must be between 2 and 100 characters")
    private String city;

    @Pattern(regexp = "^\\d{4}-\\d{2}-\\d{2}$",
            message = "Birth date must be in format YYYY-MM-DD")
    private String birthDate; // Como string para validación de formato
}
