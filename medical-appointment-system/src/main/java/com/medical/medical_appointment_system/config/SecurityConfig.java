package com.medical.medical_appointment_system.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll() // Allow access to authentication endpoints
                .requestMatchers("/api/appointments/**").permitAll() // Allow access to appointment-related endpoints
                .requestMatchers("/api/patients/**").permitAll() // Allow access to patient-related endpoints
                .requestMatchers("/api/specializations/**").permitAll() // Allow access to specialization-related endpoints
                .requestMatchers("/api/doctors/**").permitAll() // Allow access to doctor-related endpoints
                .anyRequest().authenticated() // Require authentication for all other endpoints
            )
            .csrf(csrf -> csrf.disable()) // Disable CSRF protection (if appropriate for your use case)
            .oauth2Login(oauth2 -> oauth2 // Enable OAuth2 login
                .loginPage("/oauth2/authorization/okta") // Optional: Custom login page
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/") // Redirect after logout
            );

        return http.build();
    }
}