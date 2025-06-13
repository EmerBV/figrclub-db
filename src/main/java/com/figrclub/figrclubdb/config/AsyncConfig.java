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

    @Override
    @Bean(name = "taskExecutor")
    public Executor getAsyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        executor.setCorePoolSize(corePoolSize);
        executor.setMaxPoolSize(maxPoolSize);
        executor.setQueueCapacity(queueCapacity);
        executor.setThreadNamePrefix(threadNamePrefix);

        executor.setRejectedExecutionHandler((runnable, threadPoolExecutor) -> {
            log.warn("Task rejected from thread pool. Current pool size: {}, Active threads: {}, Queue size: {}",
                    threadPoolExecutor.getPoolSize(),
                    threadPoolExecutor.getActiveCount(),
                    threadPoolExecutor.getQueue().size());
        });

        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(60);

        executor.initialize();

        log.info("Async task executor configured with core={}, max={}, queue={}",
                corePoolSize, maxPoolSize, queueCapacity);

        return executor;
    }

    @Bean(name = "emailTaskExecutor")
    public Executor emailTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(1);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("email-sender-");

        executor.setRejectedExecutionHandler((runnable, threadPoolExecutor) -> {
            log.error("Email task rejected! Queue full. Trying to run in current thread.");
            log.warn("Email queue status - Pool size: {}, Active: {}, Queue size: {}",
                    threadPoolExecutor.getPoolSize(),
                    threadPoolExecutor.getActiveCount(),
                    threadPoolExecutor.getQueue().size());

            runnable.run();
        });

        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(120);
        executor.setTaskDecorator(new EmailTaskDecorator());
        executor.initialize();

        log.info("Email task executor configured with SINGLE THREAD to prevent SMTP connection issues");

        return executor;
    }


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

    @Override
    public AsyncUncaughtExceptionHandler getAsyncUncaughtExceptionHandler() {
        return (ex, method, params) -> {
            log.error("Uncaught async exception in method '{}' with params {}: {}",
                    method.getName(), params, ex.getMessage(), ex);

            if (method.getName().contains("Email") || method.getName().contains("email")) {
                log.error("EMAIL ASYNC ERROR - Method: {}, Exception: {}",
                        method.getName(), ex.getClass().getSimpleName());

                if (params.length > 0 && params[0] instanceof String) {
                    log.error("Failed email recipient: {}", params[0]);
                }
            }
        };
    }

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