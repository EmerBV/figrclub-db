package com.figrclub.figrclubdb.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Request para actualizar a vendedor profesional con suscripción PRO
 */
@Data
public class UpgradeToProSellerRequest {

    @NotBlank(message = "Business name is required")
    @Size(min = 2, max = 200, message = "Business name must be between 2 and 200 characters")
    private String businessName;

    @Size(max = 1000, message = "Business description must not exceed 1000 characters")
    private String businessDescription;

    private String businessLogoUrl;

    @NotBlank(message = "Fiscal address is required")
    @Size(min = 10, max = 500, message = "Fiscal address must be between 10 and 500 characters")
    private String fiscalAddress;

    @NotBlank(message = "Tax ID is required")
    @Size(min = 5, max = 50, message = "Tax ID must be between 5 and 50 characters")
    private String taxId;

    @NotBlank(message = "Payment method is required")
    @Size(max = 100, message = "Payment method must not exceed 100 characters")
    private String paymentMethod;
}
