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

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.io.UnsupportedEncodingException;
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

    @Value("${app.backend.url:http://localhost:9092}")
    private String backendUrl;

    @Value("${api.prefix:/figrclub/api/v1}")
    private String apiPrefix;

    @Value("${app.mail.enabled:true}")
    private boolean mailEnabled;

    /**
     * Envía email de verificación de forma asíncrona
     */
    @Async("emailTaskExecutor")
    public CompletableFuture<Boolean> sendVerificationEmail(String toEmail, String userName, String token) {
        try {
            log.info("Preparing verification email for user: {}", toEmail);

            if (!mailEnabled) {
                log.info("Mail sending is disabled. Skipping email to: {}", toEmail);
                return CompletableFuture.completedFuture(true); // Simular éxito en modo desarrollo
            }

            String subject = "Verifica tu cuenta - FigrClub";
            String htmlContent = buildVerificationEmailContent(userName, token);

            boolean sent = sendEmailWithRetry(toEmail, subject, htmlContent, 3);

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
    @Async("emailTaskExecutor")
    public CompletableFuture<Boolean> sendWelcomeEmail(String toEmail, String userName) {
        try {
            log.info("Sending welcome email to: {}", toEmail);

            if (!mailEnabled) {
                log.info("Mail sending is disabled. Skipping welcome email to: {}", toEmail);
                return CompletableFuture.completedFuture(true);
            }

            // Agregar un pequeño delay para evitar problemas de conexión concurrente
            Thread.sleep(2000);

            String subject = "¡Bienvenido a FigrClub!";
            String htmlContent = buildWelcomeEmailContent(userName);

            boolean sent = sendEmailWithRetry(toEmail, subject, htmlContent, 3);

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
     * Método mejorado para enviar emails con reintentos más conservadores
     */
    private boolean sendEmailWithRetry(String to, String subject, String htmlContent, int maxRetries) {
        int attempts = 0;

        while (attempts < maxRetries) {
            try {
                attempts++;
                log.debug("Attempting to send email to {} (attempt {}/{})", to, attempts, maxRetries);

                // Crear una nueva instancia de MimeMessage para cada intento
                MimeMessage mimeMessage = mailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

                // Configurar el mensaje de forma simple
                helper.setFrom(fromEmail, fromName);
                helper.setTo(to);
                helper.setSubject(subject);
                helper.setText(htmlContent, true);

                // Headers básicos solamente
                mimeMessage.setHeader("Message-ID", generateMessageId());
                mimeMessage.setHeader("X-Mailer", "FigrClub-Application");

                // Enviar el mensaje
                mailSender.send(mimeMessage);

                log.debug("Email sent successfully to {} on attempt {}", to, attempts);
                return true;

            } catch (MessagingException | UnsupportedEncodingException e) {
                log.warn("Error sending email to {} (attempt {}): {}", to, attempts, e.getMessage());
                if (attempts >= maxRetries) {
                    log.error("Failed to send email to {} after {} attempts: {}", to, maxRetries, e.getMessage(), e);
                    return false;
                }
                waitBetweenRetries(attempts);

            } catch (MailException e) {
                log.warn("MailException sending email to {} (attempt {}): {}", to, attempts, e.getMessage());
                if (attempts >= maxRetries) {
                    log.error("Failed to send email to {} after {} attempts: {}", to, maxRetries, e.getMessage(), e);
                    return false;
                }
                waitBetweenRetries(attempts);

            } catch (Exception e) {
                log.error("Unexpected error sending email to {} (attempt {}): {}", to, attempts, e.getMessage(), e);
                if (attempts >= maxRetries) {
                    return false;
                }
                waitBetweenRetries(attempts);
            }
        }

        return false;
    }

    /**
     * Espera entre reintentos con backoff más conservador
     */
    private void waitBetweenRetries(int attempt) {
        try {
            // Backoff más conservador: 2s, 3s, 5s...
            long waitTime = 2000L + (attempt * 1000L);
            log.debug("Waiting {}ms before retry...", waitTime);
            Thread.sleep(waitTime);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Sleep interrupted during email retry wait");
        }
    }

    /**
     * Método privado legacy mantenido para compatibilidad (DEPRECATED)
     * @deprecated Use sendEmailWithRetry instead
     */
    @Deprecated
    private boolean sendEmail(String to, String subject, String htmlContent) {
        return sendEmailWithRetry(to, subject, htmlContent, 1);
    }

    /**
     * Construye el contenido del email de verificación - ESTILO ORIGINAL SIMPLE
     */
    private String buildVerificationEmailContent(String userName, String token) {
        String verificationUrl = backendUrl + apiPrefix + "/email/verify?token=" + token;

        return """
                <!DOCTYPE html>
                <html lang="es">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Verifica tu cuenta en FigrClub</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            margin: 0;
                            padding: 40px;
                            background-color: #f4f4f4;
                        }
                        .email-container {
                            max-width: 600px;
                            margin: 0 auto;
                            background-color: white;
                            padding: 40px;
                            border-radius: 8px;
                            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        }
                        .header {
                            text-align: center;
                            margin-bottom: 30px;
                        }
                        .header h1 {
                            color: #3498db;
                            font-size: 32px;
                            margin: 0;
                            font-weight: normal;
                        }
                        .content {
                            text-align: center;
                            margin-bottom: 30px;
                        }
                        .content h2 {
                            color: #333;
                            font-size: 24px;
                            margin-bottom: 20px;
                            font-weight: normal;
                        }
                        .content p {
                            color: #666;
                            font-size: 16px;
                            line-height: 1.5;
                            margin-bottom: 30px;
                        }
                        .button-container {
                            text-align: center;
                            margin: 30px 0;
                        }
                        .verify-button {
                            display: inline-block;
                            background-color: #3498db;
                            color: white;
                            padding: 15px 30px;
                            text-decoration: none;
                            border-radius: 5px;
                            font-size: 16px;
                            font-weight: bold;
                        }
                        .footer {
                            margin-top: 40px;
                            padding-top: 20px;
                            border-top: 1px solid #eee;
                            font-size: 14px;
                            color: #999;
                            text-align: center;
                        }
                        .url-fallback {
                            margin-top: 20px;
                            padding: 15px;
                            background-color: #f8f9fa;
                            border-radius: 5px;
                            font-size: 12px;
                            color: #666;
                            word-break: break-all;
                        }
                        .url-fallback a {
                            color: #3498db;
                            text-decoration: none;
                        }
                    </style>
                </head>
                <body>
                    <div class="email-container">
                        <div class="header">
                            <h1>Verifica tu cuenta en FigrClub</h1>
                        </div>
                        
                        <div class="content">
                            <h2>¡Hola %s!</h2>
                            <p>Para completar tu registro, por favor verifica tu email haciendo clic en el botón:</p>
                        </div>
                        
                        <div class="button-container">
                            <a href="%s" class="verify-button">Verificar Email</a>
                        </div>
                        
                        <div class="footer">
                            <p>Si no creaste esta cuenta, puedes ignorar este email.</p>
                            
                            <div class="url-fallback">
                                <p>Si tienes problemas con el botón, copia y pega esta URL en tu navegador:</p>
                                <a href="%s">%s</a>
                            </div>
                            
                            <p style="margin-top: 20px;">Este email fue enviado por <strong>FigrClub</strong></p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(userName, verificationUrl, verificationUrl, verificationUrl);
    }

    /**
     * Construye el contenido del email de bienvenida
     */
    private String buildWelcomeEmailContent(String userName) {
        return buildWelcomeEmailTemplate(userName);
    }

    /**
     * Template específico para email de bienvenida
     */
    private String buildWelcomeEmailTemplate(String userName) {
        return """
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>¡Bienvenido a FigrClub!</title>
                <style>
                    * {
                        margin: 0;
                        padding: 0;
                        box-sizing: border-box;
                    }
                    body { 
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                        line-height: 1.6; 
                        color: #333; 
                        background-color: #f5f5f5;
                        padding: 20px;
                    }
                    .email-container {
                        max-width: 600px;
                        margin: 0 auto;
                        background-color: white;
                        padding: 40px;
                        border-radius: 12px;
                        box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                    }
                    .header { 
                        text-align: center; 
                        margin-bottom: 40px; 
                        color: #2c3e50;
                    }
                    .header h1 {
                        margin: 0;
                        font-size: 28px;
                        font-weight: 600;
                    }
                    .welcome-message {
                        text-align: center;
                        margin-bottom: 30px;
                        padding: 20px;
                        background-color: #e8f5e8;
                        border-radius: 8px;
                        border-left: 4px solid #27ae60;
                    }
                    .welcome-message h2 {
                        color: #27ae60;
                        margin-bottom: 10px;
                    }
                    .content {
                        margin-bottom: 30px;
                    }
                    .content p {
                        margin-bottom: 15px;
                        font-size: 16px;
                        line-height: 1.6;
                    }
                    .features {
                        background-color: #f8f9fa;
                        padding: 20px;
                        border-radius: 8px;
                        margin: 20px 0;
                    }
                    .features h3 {
                        color: #2c3e50;
                        margin-bottom: 15px;
                    }
                    .features ul {
                        list-style: none;
                        padding: 0;
                    }
                    .features li {
                        padding: 8px 0;
                        border-bottom: 1px solid #dee2e6;
                    }
                    .features li:last-child {
                        border-bottom: none;
                    }
                    .features li:before {
                        content: "✓ ";
                        color: #27ae60;
                        font-weight: bold;
                        margin-right: 8px;
                    }
                    .footer {
                        text-align: center;
                        margin-top: 40px;
                        padding-top: 20px;
                        border-top: 1px solid #eee;
                        color: #666;
                        font-size: 14px;
                    }
                    .brand {
                        color: #3498db;
                        font-weight: 600;
                    }
                </style>
            </head>
            <body>
                <div class="email-container">
                    <div class="header">
                        <h1><span class="brand">FigrClub</span></h1>
                    </div>
                    
                    <div class="welcome-message">
                        <h2>🎉 ¡Tu cuenta ha sido verificada!</h2>
                        <p>¡Hola %s! Ya puedes utilizar todos nuestros servicios.</p>
                    </div>
                    
                    <div class="content">
                        <p>Tu verificación de email se ha completado exitosamente. 
                        Ya puedes utilizar todos nuestros servicios.</p>
                        
                        <div class="features">
                            <h3>¿Qué puedes hacer ahora?</h3>
                            <ul>
                                <li>Acceder a tu cuenta con tus credenciales</li>
                                <li>Explorar todas las funcionalidades</li>
                                <li>Configurar tu perfil</li>
                                <li>Comenzar a usar FigrClub</li>
                            </ul>
                        </div>
                    </div>
                    
                    <div class="footer">
                        <p>Gracias por unirte a <span class="brand">FigrClub</span></p>
                        <p>Si tienes alguna pregunta, no dudes en contactarnos.</p>
                        <br>
                        <p><small>Este email fue enviado porque verificaste tu cuenta en FigrClub</small></p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(userName);
    }

    /**
     * Genera un Message-ID único para cada email
     */
    private String generateMessageId() {
        return "<" + System.currentTimeMillis() + "." +
                java.util.UUID.randomUUID().toString() + "@figrclub.com>";
    }

    /**
     * Método para verificar la configuración de mail
     */
    public boolean isMailConfigured() {
        try {
            if (!mailEnabled) {
                return false;
            }
            // Intentar crear un mensaje básico para verificar configuración
            MimeMessage testMessage = mailSender.createMimeMessage();
            return testMessage != null;
        } catch (Exception e) {
            log.error("Mail configuration test failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Método para envío síncrono (para casos especiales)
     */
    public boolean sendEmailSync(String to, String subject, String htmlContent) {
        return sendEmailWithRetry(to, subject, htmlContent, 3);
    }
}