package com.figrclub.figrclubdb.util;

import jakarta.servlet.http.HttpServletRequest;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

@UtilityClass
@Slf4j
public class IpUtils {

    private static final String[] IP_HEADERS = {
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Originating-IP",
            "CF-Connecting-IP", // Cloudflare
            "X-Cluster-Client-IP",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP"
    };

    /**
     * Obtiene la dirección IP real del cliente considerando proxies y load balancers
     */
    public static String getClientIpAddress(HttpServletRequest request) {
        // Verificar headers de proxy primero
        for (String header : IP_HEADERS) {
            String ip = request.getHeader(header);
            if (isValidIp(ip)) {
                // Si hay múltiples IPs separadas por coma, tomar la primera
                if (ip.contains(",")) {
                    ip = ip.split(",")[0].trim();
                }
                log.debug("Client IP obtained from header {}: {}", header, ip);
                return ip;
            }
        }

        // Fallback a la IP remota
        String remoteAddr = request.getRemoteAddr();
        log.debug("Client IP obtained from remote address: {}", remoteAddr);
        return remoteAddr != null ? remoteAddr : "unknown";
    }

    /**
     * Valida si una IP es válida (no null, no vacía, no unknown)
     */
    private static boolean isValidIp(String ip) {
        return ip != null &&
                !ip.isEmpty() &&
                !"unknown".equalsIgnoreCase(ip) &&
                !"localhost".equalsIgnoreCase(ip) &&
                !"127.0.0.1".equals(ip) &&
                !"0:0:0:0:0:0:0:1".equals(ip);
    }

    /**
     * Normaliza una dirección IP (útil para IPv6)
     */
    public static String normalizeIp(String ip) {
        if (ip == null) return "unknown";

        // Normalizar localhost variants
        if ("127.0.0.1".equals(ip) || "::1".equals(ip) || "0:0:0:0:0:0:0:1".equals(ip)) {
            return "127.0.0.1";
        }

        return ip.trim().toLowerCase();
    }

    /**
     * Verifica si una IP está en un rango privado
     */
    public static boolean isPrivateIp(String ip) {
        if (ip == null) return false;

        return ip.startsWith("192.168.") ||
                ip.startsWith("10.") ||
                ip.startsWith("172.16.") ||
                ip.equals("127.0.0.1") ||
                ip.equals("::1");
    }
}
