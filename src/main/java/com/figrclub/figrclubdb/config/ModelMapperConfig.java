package com.figrclub.figrclubdb.config;

import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
import org.modelmapper.ModelMapper;
import org.modelmapper.PropertyMap;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ModelMapperConfig {

    @Bean
    public ModelMapper modelMapper() {
        ModelMapper mapper = new ModelMapper();

        // Configuración general
        mapper.getConfiguration()
                .setMatchingStrategy(MatchingStrategies.STRICT)
                .setFieldMatchingEnabled(true)
                .setFieldAccessLevel(org.modelmapper.config.Configuration.AccessLevel.PRIVATE);

        // Configuración específica para User -> UserDto
        mapper.addMappings(new PropertyMap<User, UserDto>() {
            @Override
            protected void configure() {
                // Mapeo directo de campos booleanos
                map().setEnabled(source.isEnabled());
                map().setAccountNonExpired(source.isAccountNonExpired());
                map().setAccountNonLocked(source.isAccountNonLocked());
                map().setCredentialsNonExpired(source.isCredentialsNonExpired());

                // Mapeo de campos de auditoría
                map().setCreatedAt(source.getCreatedAt());
                map().setUpdatedAt(source.getUpdatedAt());
                map().setCreatedBy(source.getCreatedBy());
                map().setUpdatedBy(source.getUpdatedBy());

                // Campos que se mapean manualmente en el servicio
                skip().setFullName(null);
                skip().setAdmin(false);
                skip().setRoles(null);
                skip().setEmailVerifiedAt(null);
            }
        });

        return mapper;
    }
}
