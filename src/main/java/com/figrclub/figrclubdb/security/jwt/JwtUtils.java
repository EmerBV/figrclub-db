package com.figrclub.figrclubdb.security.jwt;

import com.figrclub.figrclubdb.security.user.AppUserDetails;
import com.figrclub.figrclubdb.service.auth.JwtBlacklistService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Utilidades JWT actualizadas con soporte para blacklist
 */
@Component
@RequiredArgsConstructor
public class JwtUtils {

    @Value("${auth.token.jwtSecret}")
    private String jwtSecret;

    @Value("${auth.token.expirationInMils}")
    private int expirationTime;

    private final JwtBlacklistService blacklistService;

    /**
     * Genera un token JWT para el usuario autenticado
     */
    public String generateTokenForUser(Authentication authentication) {
        AppUserDetails userPrincipal = (AppUserDetails) authentication.getPrincipal();

        // CORREGIDO: Obtener rol único
        String role = userPrincipal.getRoleName();

        // Generar un ID único para el token (para blacklist)
        String tokenId = UUID.randomUUID().toString();
        Date expirationDate = new Date((new Date()).getTime() + expirationTime);

        return Jwts.builder()
                .setSubject(userPrincipal.getEmail())
                .setId(tokenId) // JTI claim para identificar el token
                .claim("id", userPrincipal.getId())
                .claim("role", role) // Rol único en lugar de lista
                .claim("email", userPrincipal.getEmail())
                .setIssuedAt(new Date())
                .setExpiration(expirationDate)
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    /**
     * Obtiene el username/email del token
     */
    public String getUsernameFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /**
     * Obtiene el ID del token (JTI claim)
     */
    public String getTokenId(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getId();
    }

    /**
     * Obtiene la fecha de expiración del token
     */
    public LocalDateTime getTokenExpiration(String token) {
        Date expiration = Jwts.parserBuilder()
                .setSigningKey(key())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();

        return LocalDateTime.ofInstant(expiration.toInstant(), ZoneId.systemDefault());
    }

    /**
     * Valida el token JWT incluyendo verificación de blacklist
     */
    public boolean validateToken(String token) {
        try {
            // Primero verificar la firma y estructura del token
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // Verificar si el token está en la blacklist
            String tokenId = claims.getId();
            if (tokenId != null && blacklistService.isTokenBlacklisted(tokenId)) {
                throw new JwtException("Token has been invalidated");
            }

            return true;

        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException |
                 SignatureException | IllegalArgumentException e) {
            throw new JwtException(e.getMessage());
        }
    }

    /**
     * Invalida un token agregándolo a la blacklist
     */
    public void invalidateToken(String token) {
        try {
            String tokenId = getTokenId(token);
            LocalDateTime expiration = getTokenExpiration(token);

            if (tokenId != null) {
                blacklistService.blacklistToken(tokenId, expiration);
            }
        } catch (Exception e) {
            // Si hay error parseando el token, probablemente ya sea inválido
            // Log del error pero no falla el logout
            System.err.println("Error invalidating token: " + e.getMessage());
        }
    }

    /**
     * Extrae el token del header Authorization
     */
    public String extractTokenFromRequest(jakarta.servlet.http.HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
