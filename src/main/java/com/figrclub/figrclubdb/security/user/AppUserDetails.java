package com.figrclub.figrclubdb.security.user;

import com.figrclub.figrclubdb.domain.model.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AppUserDetails implements UserDetails {

    private Long id;
    private String email;
    private String password;
    private boolean isEnabled;
    private boolean isAccountNonExpired;
    private boolean isAccountNonLocked;
    private boolean isCredentialsNonExpired;
    private Collection<GrantedAuthority> authorities;

    /**
     * MÉTODO CORREGIDO: Trabajar con rol único en lugar de colección
     */
    public static AppUserDetails buildUserDetails(User user) {
        // ANTES: user.getRoles().stream()...
        // AHORA: Trabajar con rol único

        List<GrantedAuthority> authorities;

        if (user.getRole() != null) {
            // Crear authority para el rol único
            authorities = List.of(new SimpleGrantedAuthority(user.getRole().getName()));
        } else {
            // Fallback: usuario sin rol (no debería pasar en producción)
            authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        }

        return new AppUserDetails(
                user.getId(),
                user.getEmail(),
                user.getPassword(),
                user.isEnabled(),
                user.isAccountNonExpired(),
                user.isAccountNonLocked(),
                user.isCredentialsNonExpired(),
                authorities
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return isAccountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return isAccountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return isCredentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return isEnabled;
    }

    // ===== MÉTODOS DE UTILIDAD ADICIONALES =====

    /**
     * Obtiene el nombre del rol principal del usuario
     */
    public String getRoleName() {
        return authorities.stream()
                .findFirst()
                .map(GrantedAuthority::getAuthority)
                .orElse("ROLE_USER");
    }

    /**
     * Verifica si el usuario tiene un rol específico
     */
    public boolean hasRole(String roleName) {
        return authorities.stream()
                .anyMatch(auth -> auth.getAuthority().equals(roleName));
    }

    /**
     * Verifica si el usuario es administrador
     */
    public boolean isAdmin() {
        return hasRole("ROLE_ADMIN");
    }
}
