package com.figrclub.figrclubdb.dto;

/**
 * Record para estadísticas de usuarios
 * Reemplaza el stats.totalUsers() y stats.proSellers() que aparecían en el código
 */
public record UserStatistics(
        long totalUsers,
        long activeUsers,
        long verifiedUsers,
        long adminUsers,
        long regularUsers,
        long proSellers,
        long individualUsers,
        long freeUsers,
        long proUsers
) {

    /**
     * Calcula el porcentaje de conversión a Pro Seller
     */
    public double getProSellerConversionRate() {
        return totalUsers > 0 ? (double) proSellers / totalUsers * 100 : 0.0;
    }

    /**
     * Calcula el porcentaje de usuarios activos
     */
    public double getActiveUserPercentage() {
        return totalUsers > 0 ? (double) activeUsers / totalUsers * 100 : 0.0;
    }

    /**
     * Calcula el porcentaje de usuarios verificados
     */
    public double getVerificationRate() {
        return totalUsers > 0 ? (double) verifiedUsers / totalUsers * 100 : 0.0;
    }

    /**
     * Calcula el porcentaje de administradores
     */
    public double getAdminPercentage() {
        return totalUsers > 0 ? (double) adminUsers / totalUsers * 100 : 0.0;
    }
}
