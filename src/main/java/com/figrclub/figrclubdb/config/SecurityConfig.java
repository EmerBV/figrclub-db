package com.figrclub.figrclubdb.config;

import com.figrclub.figrclubdb.security.filter.RateLimitingFilter;
import com.figrclub.figrclubdb.security.jwt.AuthTokenFilter;
import com.figrclub.figrclubdb.security.jwt.JwtAuthEntryPoint;
import com.figrclub.figrclubdb.security.user.AppUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final AppUserDetailsService userDetailsService;
    private final JwtAuthEntryPoint authEntryPoint;
    private final RateLimitingFilter rateLimitingFilter; // AÑADIDO

    private static final List<String> SECURED_URLS = List.of(
            "/figrclub/api/v1/users/**",
            "/figrclub/api/v1/admin/**",
            "/figrclub/api/v1/password/change",
            "/figrclub/api/v1/rate-limit/admin/**" // AÑADIDO
    );

    private static final String[] PUBLIC_URLS = {
            "/figrclub/api/v1/auth/**",
            "/figrclub/api/v1/users/add", // Registro público
            "/figrclub/api/v1/password/reset-request",
            "/figrclub/api/v1/password/reset-confirm",
            "/figrclub/api/v1/password/validate-token",
            "/figrclub/api/v1/rate-limit/status", // AÑADIDO
            "/actuator/health",
            "/api-docs/**", // Actualizado según tu configuración
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/swagger-resources/**",
            "/webjars/**"
    };

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthTokenFilter authTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        var authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .exceptionHandling(exception -> exception.authenticationEntryPoint(authEntryPoint))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers(PUBLIC_URLS).permitAll()
                                .requestMatchers("/figrclub/api/v1/users/admin/**").hasRole("ADMIN")
                                .requestMatchers("/figrclub/api/v1/rate-limit/admin/**").hasRole("ADMIN") // AÑADIDO
                                .requestMatchers(SECURED_URLS.toArray(String[]::new)).authenticated()
                                .anyRequest().permitAll()
                );

        http.authenticationProvider(daoAuthenticationProvider());

        // AÑADIDO: Agregar filtros en el orden correcto
        // RateLimitingFilter DEBE ir antes que AuthTokenFilter
        http.addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(@NonNull CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:3000", "http://localhost:5173", "http://localhost:8080")
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH")
                        .allowedHeaders("*")
                        .exposedHeaders("Authorization", "Content-Type", "X-RateLimit-*", "Retry-After") // AÑADIDO headers de rate limiting
                        .allowCredentials(true)
                        .maxAge(3600);
            }
        };
    }
}
