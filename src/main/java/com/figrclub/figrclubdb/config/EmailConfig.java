package com.figrclub.figrclubdb.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Properties;

/**
 * Configuración simplificada para el servicio de email
 * Compatible con la configuración existente en application.properties
 */
@Configuration
@Slf4j
public class EmailConfig {

    @Value("${spring.mail.host}")
    private String mailHost;

    @Value("${spring.mail.port}")
    private int mailPort;

    @Value("${spring.mail.username}")
    private String mailUsername;

    @Value("${spring.mail.password}")
    private String mailPassword;

    @Value("${spring.mail.protocol}")
    private String mailProtocol;

    @Value("${app.mail.enabled:true}")
    private boolean mailEnabled;

    /**
     * Configuración del JavaMailSender compatible con application.properties
     * Se mantiene la configuración existente pero optimizada para evitar errores de conexión
     */
    @Bean
    public JavaMailSender getJavaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();

        if (!mailEnabled) {
            log.info("Mail is disabled. Creating mock mail sender.");
            return mailSender;
        }

        // Configuración básica desde application.properties
        mailSender.setHost(mailHost);
        mailSender.setPort(mailPort);
        mailSender.setUsername(mailUsername);
        mailSender.setPassword(mailPassword);
        mailSender.setProtocol(mailProtocol);

        Properties props = mailSender.getJavaMailProperties();

        // CONFIGURACIÓN BÁSICA SMTP (compatible con tu application.properties)
        props.put("mail.transport.protocol", mailProtocol);
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.starttls.required", "true");

        // CONFIGURACIONES CRÍTICAS PARA EVITAR ERRORES DE CONEXIÓN

        // Timeouts desde application.properties
        props.put("mail.smtp.connectiontimeout", "10000");
        props.put("mail.smtp.timeout", "15000");
        props.put("mail.smtp.writetimeout", "10000");

        // Pool de conexiones mínimo para evitar reutilización problemática
        props.put("mail.smtp.connectionpoolsize", "1");
        props.put("mail.smtp.connectionpooltimeout", "300000");

        // Configuración SSL simplificada para Gmail
        if (mailHost.contains("gmail.com")) {
            props.put("mail.smtp.ssl.trust", "smtp.gmail.com");
            props.put("mail.smtp.ssl.protocols", "TLSv1.2");
            // NO especificar cipher suites - dejar que Java elija automáticamente
        }

        // Headers básicos
        props.put("mail.smtp.sendpartial", "true");

        // Debug deshabilitado por defecto (se puede habilitar desde application.properties)
        props.put("mail.debug", "false");

        log.info("JavaMailSender configured - Host: {}, Port: {}, Username: {}",
                mailHost, mailPort, mailUsername);

        return mailSender;
    }

    /**
     * Método de utilidad para validar configuración de email
     */
    public boolean validateEmailConfiguration() {
        try {
            if (!mailEnabled) {
                log.info("Mail is disabled");
                return false;
            }

            if (mailUsername.isEmpty() || mailPassword.isEmpty()) {
                log.warn("Mail credentials are not configured");
                return false;
            }

            log.info("Email configuration appears valid");
            return true;

        } catch (Exception e) {
            log.error("Error validating email configuration: {}", e.getMessage());
            return false;
        }
    }
}