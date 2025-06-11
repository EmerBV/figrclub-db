package com.figrclub.figrclubdb.request;

import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UserUpdateRequest {

    @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
    private String firstName;

    @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
    private String lastName;

    // Nota: Email no se puede cambiar por razones de seguridad
    // Password se maneja en un endpoint separado para mayor seguridad
}
