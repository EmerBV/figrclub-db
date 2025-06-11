package com.figrclub.figrclubdb.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.interceptor.AsyncUncaughtExceptionHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.AsyncConfigurer;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

/**
 * Configuración para procesamiento asíncrono
 * Especialmente importante para el envío de emails
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
     * Configuración del executor para tareas asíncronas
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
     */
    @Bean(name = "emailTaskExecutor")
    public Executor emailTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(3);
        executor.setQueueCapacity(50);
        executor.setThreadNamePrefix("email-sender-");

        // Para emails, queremos asegurar que se procesen
        executor.setRejectedExecutionHandler((runnable, threadPoolExecutor) -> {
            log.error("Email task rejected! This should not happen. Trying to run in current thread.");
            runnable.run();
        });

        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);

        executor.initialize();

        log.info("Email task executor configured");

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

            // Aquí podrías agregar lógica adicional como:
            // - Enviar notificación a administradores
            // - Guardar en base de datos para debugging
            // - Métricas de errores
        };
    }
}
