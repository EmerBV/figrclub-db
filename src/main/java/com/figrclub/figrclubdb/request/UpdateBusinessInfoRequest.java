package com.figrclub.figrclubdb.request;

import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Request para actualizar información de negocio (solo para vendedores existentes)
 */
@Data
public class UpdateBusinessInfoRequest {

    @Size(min = 2, max = 200, message = "Business name must be between 2 and 200 characters")
    private String businessName;

    @Size(max = 1000, message = "Business description must not exceed 1000 characters")
    private String businessDescription;

    private String businessLogoUrl;
}
