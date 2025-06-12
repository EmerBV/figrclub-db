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

                // Mapeo de nuevos campos de suscripción y tipo de usuario
                map().setUserType(source.getUserType());
                map().setSubscriptionType(source.getSubscriptionType());
                map().setUpgradedToProAt(source.getUpgradedToProAt());

                // Mapeo de campos de contacto
                map().setPhone(source.getPhone());
                map().setCountry(source.getCountry());
                map().setCity(source.getCity());
                map().setBirthDate(source.getBirthDate());

                // Mapeo de campos de negocio (solo para vendedores profesionales)
                map().setBusinessName(source.getBusinessName());
                map().setBusinessDescription(source.getBusinessDescription());
                map().setBusinessLogoUrl(source.getBusinessLogoUrl());
                map().setFiscalAddress(source.getFiscalAddress());
                map().setTaxId(source.getTaxId());
                map().setPaymentMethod(source.getPaymentMethod());

                // Campos que se mapean manualmente en el servicio
                skip().setFullName(null);
                skip().setDisplayName(null);
                skip().setAdmin(false);
                skip().setRoles(null);
                skip().setEmailVerifiedAt(null);
            }
        });

        return mapper;
    }
}
