package com.figrclub.figrclubdb.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiResponse {
    private String message;
    private Object data;

    @Builder.Default
    private int status = 200;

    @Builder.Default
    private long timestamp = System.currentTimeMillis();

    // Constructor de compatibilidad con el código existente
    public ApiResponse(String message, Object data) {
        this.message = message;
        this.data = data;
        this.status = 200;
        this.timestamp = System.currentTimeMillis();
    }
}
