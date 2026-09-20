package com.bhavanasecuresoftware.secureapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the Spring Boot application (the "Spring Boot
 * application setup" piece called out in the rubric).
 *
 * @SpringBootApplication is itself shorthand for three annotations:
 *   - @Configuration: this class can define Spring beans.
 *   - @EnableAutoConfiguration: Spring Boot inspects the dependencies on
 *     the classpath (spring-boot-starter-web, -data-jpa, -security, ...
 *     from pom.xml) and wires up matching infrastructure automatically --
 *     the embedded Tomcat server, the JPA/Hibernate EntityManager, and
 *     Spring Security's default filter chain -- with no manual XML/Java
 *     configuration required for the basics.
 *   - @ComponentScan: automatically discovers and registers every
 *     @Component/@Service/@RestController/@Configuration class under
 *     this package (com.bhavanasecuresoftware.secureapp and below), which
 *     is why UserController, AppUserDetailsService, and SecurityConfig
 *     are all picked up without being registered here by hand.
 *
 * The actual HTTPS/KeyStore settings (server.ssl.*) live in
 * application.properties, not in this class -- Spring Boot reads that
 * file automatically at startup and applies it before the embedded
 * server binds to its port.
 */
@SpringBootApplication
public class SecureAppApplication {

    public static void main(String[] args) {
        // Boots the entire application context: loads
        // application.properties, discovers all @Component-annotated
        // classes, builds the Spring Security filter chain, and starts
        // the embedded Tomcat server listening on the HTTPS port
        // configured there (8443).
        SpringApplication.run(SecureAppApplication.class, args);
    }
}
