package com.figrclub.figrclubdb.request;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class BlockRequest {

    @NotBlank(message = "Identifier (IP or email) is required")
    @Size(max = 100, message = "Identifier must not exceed 100 characters")
    private String identifier;

    @Min(value = 1, message = "Duration must be at least 1 minute")
    @Max(value = 10080, message = "Duration must not exceed 7 days (10080 minutes)")
    private int durationMinutes;

    @NotBlank(message = "Reason is required")
    @Size(max = 500, message = "Reason must not exceed 500 characters")
    private String reason;
}
