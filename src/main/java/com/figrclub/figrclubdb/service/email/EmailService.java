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
import jakarta.mail.internet.InternetAddress;
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

            boolean sent = sendEmail(toEmail, subject, htmlContent);

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

            String subject = "¡Bienvenido a FigrClub!";
            String htmlContent = buildWelcomeEmailContent(userName);

            boolean sent = sendEmail(toEmail, subject, htmlContent);

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
     * Método privado mejorado para enviar emails con mejor manejo de errores
     */
    private boolean sendEmail(String to, String subject, String htmlContent) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

            // CORRECCIÓN: Usar InternetAddress para manejar el nombre del remitente
            try {
                InternetAddress fromAddress = new InternetAddress(fromEmail, fromName, "UTF-8");
                helper.setFrom(fromAddress);
            } catch (UnsupportedEncodingException e) {
                log.warn("Error setting sender name, using email only: {}", e.getMessage());
                helper.setFrom(fromEmail); // Fallback a solo email
            }

            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);

            // Agregar headers adicionales para mejorar la entrega
            mimeMessage.setHeader("Message-ID", generateMessageId());
            mimeMessage.setHeader("X-Mailer", "FigrClub-Application");

            mailSender.send(mimeMessage);
            return true;

        } catch (MessagingException e) {
            log.error("MessagingException sending email to {}: {}", to, e.getMessage(), e);
            return false;
        } catch (MailException e) {
            log.error("MailException sending email to {}: {}", to, e.getMessage(), e);
            return false;
        } catch (Exception e) {
            log.error("Unexpected error sending email to {}: {}", to, e.getMessage(), e);
            return false;
        }
    }

    /**
     * Construye el contenido del email de verificación
     */
    private String buildVerificationEmailContent(String userName, String token) {
        String verificationUrl = backendUrl + apiPrefix + "/email/verify?token=" + token;

        return buildSimpleEmailTemplate(
                "Verifica tu cuenta en FigrClub",
                "¡Hola " + userName + "!",
                "Para completar tu registro, por favor verifica tu email haciendo clic en el botón:",
                "Verificar Email",
                verificationUrl,
                "Si no creaste esta cuenta, puedes ignorar este email."
        );
    }

    /**
     * Construye el contenido del email de bienvenida
     */
    private String buildWelcomeEmailContent(String userName) {
        return buildWelcomeEmailTemplate(userName);
    }

    /**
     * Construye un template simple de email
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
                            color: #3498db;
                        }
                        .content { 
                            margin-bottom: 40px; 
                            text-align: center;
                        }
                        .content p {
                            margin-bottom: 20px;
                            font-size: 16px;
                            line-height: 1.6;
                        }
                        .button {
                            display: inline-block;
                            padding: 16px 32px;
                            background: linear-gradient(135deg, #3498db, #2980b9);
                            color: white;
                            text-decoration: none;
                            border-radius: 8px;
                            font-weight: 600;
                            font-size: 16px;
                            margin: 30px 0;
                            transition: all 0.3s ease;
                            box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3);
                        }
                        .button:hover {
                            background: linear-gradient(135deg, #2980b9, #2471a3);
                            box-shadow: 0 6px 20px rgba(52, 152, 219, 0.4);
                        }
                        .footer {
                            margin-top: 40px;
                            padding-top: 30px;
                            border-top: 1px solid #eee;
                            font-size: 14px;
                            color: #666;
                            text-align: center;
                            line-height: 1.5;
                        }
                        .footer p {
                            margin-bottom: 10px;
                        }
                        .footer .url {
                            word-break: break-all;
                            color: #3498db;
                            font-size: 12px;
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
                            <h1>%s</h1>
                        </div>
                        
                        <div class="content">
                            <p><strong>%s</strong></p>
                            <p>%s</p>
                            
                            <a href="%s" class="button">%s</a>
                        </div>
                        
                        <div class="footer">
                            <p>%s</p>
                            <p>Si tienes problemas con el botón, copia y pega esta URL en tu navegador:</p>
                            <p class="url">%s</p>
                            <br>
                            <p><small>Este email fue enviado por <span class="brand">FigrClub</span></small></p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(title, title, greeting, message, buttonUrl, buttonText, footer, buttonUrl);
    }

    /**
     * Construye el contenido del email de bienvenida (SIN botón de login)
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
                        color: #3498db;
                    }
                    .success-icon {
                        width: 80px;
                        height: 80px;
                        background: #4CAF50;
                        border-radius: 50%%;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        margin: 0 auto 30px;
                        font-size: 40px;
                        color: white;
                    }
                    .content { 
                        margin-bottom: 40px; 
                        text-align: center;
                    }
                    .content p {
                        margin-bottom: 20px;
                        font-size: 16px;
                        line-height: 1.6;
                    }
                    .welcome-message {
                        background: linear-gradient(135deg, #3498db, #2980b9);
                        color: white;
                        padding: 30px;
                        border-radius: 12px;
                        margin: 30px 0;
                    }
                    .welcome-message h2 {
                        margin-bottom: 15px;
                        font-size: 24px;
                    }
                    .features {
                        text-align: left;
                        margin: 30px 0;
                    }
                    .features ul {
                        list-style: none;
                        padding: 0;
                    }
                    .features li {
                        padding: 10px 0;
                        padding-left: 30px;
                        position: relative;
                    }
                    .features li:before {
                        content: "✓";
                        position: absolute;
                        left: 0;
                        color: #4CAF50;
                        font-weight: bold;
                        font-size: 18px;
                    }
                    .footer {
                        margin-top: 40px;
                        padding-top: 30px;
                        border-top: 1px solid #eee;
                        font-size: 14px;
                        color: #666;
                        text-align: center;
                        line-height: 1.5;
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
                        <div class="success-icon">✓</div>
                        <h1>¡Bienvenido a FigrClub!</h1>
                    </div>
                    
                    <div class="content">
                        <div class="welcome-message">
                            <h2>¡Hola %s!</h2>
                            <p>Tu cuenta ha sido verificada exitosamente y ya forma parte de la comunidad FigrClub.</p>
                        </div>
                        
                        <p>Tu registro se ha completado y tu email está verificado. Ya puedes utilizar todos nuestros servicios.</p>
                        
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
        return sendEmail(to, subject, htmlContent);
    }
}
