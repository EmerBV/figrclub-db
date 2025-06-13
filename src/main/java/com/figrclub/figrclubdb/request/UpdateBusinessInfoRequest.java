package com.figrclub.figrclubdb.request;

import jakarta.validation.constraints.Size;
import lombok.Data;

import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Request para actualizar información de negocio del usuario (solo vendedores profesionales)
 */
@Data
public class UpdateBusinessInfoRequest {

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
}
