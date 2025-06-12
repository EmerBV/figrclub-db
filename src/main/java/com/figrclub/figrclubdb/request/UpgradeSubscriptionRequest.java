package com.figrclub.figrclubdb.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Request para actualizar solo la suscripción a PRO
 */
@Data
public class UpgradeSubscriptionRequest {

    @NotBlank(message = "Payment method is required")
    @Size(max = 100, message = "Payment method must not exceed 100 characters")
    private String paymentMethod;
}
