package com.figrclub.figrclubdb.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.interceptor.AsyncUncaughtExceptionHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskDecorator;
import org.springframework.scheduling.annotation.AsyncConfigurer;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

/**
 * Configuración mejorada para procesamiento asíncrono
 * Especialmente optimizada para el envío de emails secuencial
 */
@Configuration
@EnableAsync
@EnableScheduling
@Slf4j
public class AsyncConfig implements AsyncConfigurer {

    @Value("${spring.task.execution.pool.core-size:2}")
    private int corePoolSize;

    @Value("${spring.task.execution.pool.max-size:4}")
    private int maxPoolSize;

    @Value("${spring.task.execution.pool.queue-capacity:100}")
    private int queueCapacity;

    @Value("${spring.task.execution.thread-name-prefix:email-task-}")
    private String threadNamePrefix;

    /**
     * Configuración del executor para tareas asíncronas generales
     */
    @Override
    @Bean(name = "taskExecutor")
    public Executor getAsyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        executor.setCorePoolSize(corePoolSize);
        executor.setMaxPoolSize(maxPoolSize);
        executor.setQueueCapacity(queueCapacity);
        executor.setThreadNamePrefix(threadNamePrefix);

        // Configuración de rechazo de tareas
        executor.setRejectedExecutionHandler((runnable, threadPoolExecutor) -> {
            log.warn("Task rejected from thread pool. Current pool size: {}, Active threads: {}, Queue size: {}",
                    threadPoolExecutor.getPoolSize(),
                    threadPoolExecutor.getActiveCount(),
                    threadPoolExecutor.getQueue().size());
        });

        // Esperar a que terminen las tareas al shutdown
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(60);

        executor.initialize();

        log.info("Async task executor configured with core={}, max={}, queue={}",
                corePoolSize, maxPoolSize, queueCapacity);

        return executor;
    }

    /**
     * Configuración específica para envío de emails
     * CRÍTICO: Se configura con un solo hilo para envío secuencial
     */
    @Bean(name = "emailTaskExecutor")
    public Executor emailTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        // CONFIGURACIÓN CRÍTICA: Un solo hilo para envíos secuenciales
        // Esto evita problemas de conexiones concurrentes al servidor SMTP
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(1); // SOLO UN HILO - CRÍTICO
        executor.setQueueCapacity(100); // Cola grande para manejar múltiples emails
        executor.setThreadNamePrefix("email-sender-");

        // Para emails, queremos asegurar que se procesen siempre
        executor.setRejectedExecutionHandler((runnable, threadPoolExecutor) -> {
            log.error("Email task rejected! Queue full. Trying to run in current thread.");
            log.warn("Email queue status - Pool size: {}, Active: {}, Queue size: {}",
                    threadPoolExecutor.getPoolSize(),
                    threadPoolExecutor.getActiveCount(),
                    threadPoolExecutor.getQueue().size());

            // Como último recurso, ejecutar en el hilo actual
            runnable.run();
        });

        // Configuración de cierre elegante
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(120); // Más tiempo para emails

        // Decorador de tareas para logging mejorado
        executor.setTaskDecorator(new EmailTaskDecorator());

        executor.initialize();

        log.info("Email task executor configured with SINGLE THREAD to prevent SMTP connection issues");

        return executor;
    }

    /**
     * Configuración adicional para tareas de limpieza y mantenimiento
     */
    @Bean(name = "maintenanceTaskExecutor")
    public Executor maintenanceTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(2);
        executor.setQueueCapacity(10);
        executor.setThreadNamePrefix("maintenance-");

        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);

        executor.initialize();

        log.info("Maintenance task executor configured");

        return executor;
    }

    /**
     * Manejador de excepciones no capturadas en tareas asíncronas
     */
    @Override
    public AsyncUncaughtExceptionHandler getAsyncUncaughtExceptionHandler() {
        return (ex, method, params) -> {
            log.error("Uncaught async exception in method '{}' with params {}: {}",
                    method.getName(), params, ex.getMessage(), ex);

            // Log adicional para métodos de email
            if (method.getName().contains("Email") || method.getName().contains("email")) {
                log.error("EMAIL ASYNC ERROR - Method: {}, Exception: {}",
                        method.getName(), ex.getClass().getSimpleName());

                // Aquí podrías agregar lógica adicional como:
                // - Enviar notificación a administradores
                // - Guardar en base de datos para debugging
                // - Métricas de errores de email

                if (params.length > 0 && params[0] instanceof String) {
                    log.error("Failed email recipient: {}", params[0]);
                }
            }
        };
    }

    /**
     * Decorador personalizado para tareas de email
     * Proporciona contexto adicional y manejo de errores
     */
    private static class EmailTaskDecorator implements TaskDecorator {
        @Override
        public Runnable decorate(Runnable runnable) {
            return () -> {
                String threadName = Thread.currentThread().getName();
                long startTime = System.currentTimeMillis();

                try {
                    log.debug("Starting email task in thread: {}", threadName);
                    runnable.run();

                } catch (Exception e) {
                    log.error("Error in email task thread {}: {}", threadName, e.getMessage(), e);
                    throw e;

                } finally {
                    long duration = System.currentTimeMillis() - startTime;
                    log.debug("Email task completed in thread: {} ({}ms)", threadName, duration);

                    // Pequeña pausa para dar tiempo entre tareas de email
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                }
            };
        }
    }
}