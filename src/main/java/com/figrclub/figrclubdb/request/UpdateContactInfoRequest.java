package com.figrclub.figrclubdb.request;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

import jakarta.validation.constraints.Size;
import lombok.Data;

import java.time.LocalDate;

/**
 * Request para actualizar información de contacto del usuario
 */
@Data
public class UpdateContactInfoRequest {

    @Size(max = 20, message = "Phone number cannot exceed 20 characters")
    private String phone;

    @Size(max = 100, message = "Country name cannot exceed 100 characters")
    private String country;

    @Size(max = 100, message = "City name cannot exceed 100 characters")
    private String city;

    private LocalDate birthDate;
}
