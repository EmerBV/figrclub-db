package com.figrclub.figrclubdb.service.email;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.util.concurrent.CompletableFuture;

/**
 * Servicio para envío de emails
 * Maneja el envío asíncrono de correos electrónicos
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    @Value("${app.mail.from:noreply@figrclub.com}")
    private String fromEmail;

    @Value("${app.mail.from-name:FigrClub}")
    private String fromName;

    @Value("${app.frontend.url:http://localhost:3000}")
    private String frontendUrl;

    /**
     * Envía email de verificación de forma asíncrona
     */
    @Async
    public CompletableFuture<Boolean> sendVerificationEmail(String toEmail, String userName, String token) {
        try {
            log.info("Preparing verification email for user: {}", toEmail);

            Context context = new Context();
            context.setVariable("userName", userName);
            context.setVariable("verificationUrl", frontendUrl + "/verify-email?token=" + token);
            context.setVariable("frontendUrl", frontendUrl);
            context.setVariable("companyName", "FigrClub");

            String htmlContent = buildSimpleEmailTemplate(
                    "Verifica tu cuenta en FigrClub",
                    "Hola " + userName + ",",
                    "Para completar tu registro, por favor verifica tu email haciendo clic en el botón:",
                    "Verificar Email",
                    frontendUrl + "/verify-email?token=" + token,
                    "Si no creaste esta cuenta, puedes ignorar este email."
            );

            boolean sent = sendEmail(toEmail, "Verifica tu cuenta - FigrClub", htmlContent);

            if (sent) {
                log.info("Verification email sent successfully to: {}", toEmail);
            } else {
                log.error("Failed to send verification email to: {}", toEmail);
            }

            return CompletableFuture.completedFuture(sent);

        } catch (Exception e) {
            log.error("Error sending verification email to {}: {}", toEmail, e.getMessage(), e);
            return CompletableFuture.completedFuture(false);
        }
    }

    /**
     * Envía email de confirmación cuando la verificación es exitosa
     */
    @Async
    public CompletableFuture<Boolean> sendWelcomeEmail(String toEmail, String userName) {
        try {
            log.info("Sending welcome email to: {}", toEmail);

            String htmlContent = buildSimpleEmailTemplate(
                    "¡Bienvenido a FigrClub!",
                    "¡Hola " + userName + "!",
                    "Tu cuenta ha sido verificada exitosamente. Ya puedes comenzar a usar FigrClub.",
                    "Acceder a FigrClub",
                    frontendUrl + "/login",
                    "Gracias por unirte a nuestra comunidad."
            );

            boolean sent = sendEmail(toEmail, "¡Bienvenido a FigrClub!", htmlContent);

            if (sent) {
                log.info("Welcome email sent successfully to: {}", toEmail);
            } else {
                log.error("Failed to send welcome email to: {}", toEmail);
            }

            return CompletableFuture.completedFuture(sent);

        } catch (Exception e) {
            log.error("Error sending welcome email to {}: {}", toEmail, e.getMessage(), e);
            return CompletableFuture.completedFuture(false);
        }
    }

    /**
     * Método privado para enviar emails
     */
    private boolean sendEmail(String to, String subject, String htmlContent) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

            helper.setFrom(fromEmail, fromName);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);

            mailSender.send(mimeMessage);
            return true;

        } catch (MessagingException | MailException e) {
            log.error("Error sending email to {}: {}", to, e.getMessage(), e);
            return false;
        }
    }

    /**
     * Construye un template simple de email sin usar Thymeleaf
     * Para casos donde no se tiene configurado Thymeleaf o se prefiere simplicidad
     */
    private String buildSimpleEmailTemplate(String title, String greeting, String message,
                                            String buttonText, String buttonUrl, String footer) {
        return """
                <!DOCTYPE html>
                <html lang="es">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>%s</title>
                    <style>
                        body { 
                            font-family: Arial, sans-serif; 
                            line-height: 1.6; 
                            color: #333; 
                            max-width: 600px; 
                            margin: 0 auto; 
                            padding: 20px; 
                            background-color: #f4f4f4;
                        }
                        .email-container {
                            background-color: white;
                            padding: 30px;
                            border-radius: 10px;
                            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        }
                        .header { 
                            text-align: center; 
                            margin-bottom: 30px; 
                            color: #2c3e50;
                        }
                        .header h1 {
                            margin: 0;
                            font-size: 24px;
                        }
                        .content { 
                            margin-bottom: 30px; 
                        }
                        .button {
                            display: inline-block;
                            padding: 12px 30px;
                            background-color: #3498db;
                            color: white;
                            text-decoration: none;
                            border-radius: 5px;
                            font-weight: bold;
                            margin: 20px 0;
                        }
                        .button:hover {
                            background-color: #2980b9;
                        }
                        .footer {
                            margin-top: 30px;
                            padding-top: 20px;
                            border-top: 1px solid #eee;
                            font-size: 14px;
                            color: #666;
                            text-align: center;
                        }
                        .center { text-align: center; }
                    </style>
                </head>
                <body>
                    <div class="email-container">
                        <div class="header">
                            <h1>%s</h1>
                        </div>
                        
                        <div class="content">
                            <p><strong>%s</strong></p>
                            <p>%s</p>
                            
                            <div class="center">
                                <a href="%s" class="button">%s</a>
                            </div>
                        </div>
                        
                        <div class="footer">
                            <p>%s</p>
                            <p><small>Este email fue enviado por FigrClub. Si tienes problemas con el botón, copia y pega esta URL en tu navegador: %s</small></p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(title, title, greeting, message, buttonUrl, buttonText, footer, buttonUrl);
    }
}
