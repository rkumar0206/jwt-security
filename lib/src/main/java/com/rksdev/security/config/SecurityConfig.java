package com.rksdev.security.config;

import com.rksdev.config.JwtProperties;
import com.rksdev.security.api.JwtCustomClaimsProvider;
import com.rksdev.security.filter.JwtAuthenticationFilter;
import com.rksdev.security.service.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collections;

@AutoConfiguration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(JwtProperties.class)
@ComponentScan(basePackages = "com.rksdev.security")
@ConditionalOnProperty(prefix = "jwt.properties", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SecurityConfig {

    private final JwtProperties jwtProperties;

    public SecurityConfig(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    @Bean
    public JwtService jwtService(JwtProperties jwtProperties, JwtCustomClaimsProvider jwtCustomClaimsProvider) {
        return new JwtService(jwtProperties, jwtCustomClaimsProvider);
    }

    /**
     * Fallback strategy: creates an empty map for custom claims if host app doesn't specify one.
     */
    @Bean
    @ConditionalOnMissingBean(JwtCustomClaimsProvider.class)
    public JwtCustomClaimsProvider defaultCustomClaimsProvider() {
        return authentication -> Collections.emptyMap();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtService jwtService) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 🎯 FORCE 401 FOR UNAUTHENTICATED / EXPIRED COOKIE REQUESTS
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.setContentType("application/json");
                            response.setCharacterEncoding("UTF-8");

                            String jsonErrorResponse = """
                                    {
                                        "status": 401,
                                        "error": "Unauthorized",
                                        "message": "Full authentication is required to access this resource."
                                    }
                                    """;

                            response.getWriter().write(jsonErrorResponse);
                            response.getWriter().flush();
                        })
                )
                .authorizeHttpRequests(auth -> {

                    // 1. Map open public pathways
                    if (!jwtProperties.publicEndpoints().isEmpty()) {
                        auth.requestMatchers(jwtProperties.publicEndpoints().toArray(new String[0])).permitAll();
                    }

                    // 2. Process and apply custom dynamic role constraints from property mappings
                    for (JwtProperties.RoleMapping mapping : jwtProperties.roleMappings()) {
                        auth.requestMatchers(mapping.pattern())
                                .hasAnyAuthority(mapping.roles().toArray(new String[0]));
                    }

                    // 3. Fallback gatekeeper
                    auth.anyRequest().authenticated();
                });

        // Inject our stateless parsing filter right before UsernamePasswordAuthenticationFilter runs
        http.addFilterBefore(new JwtAuthenticationFilter(jwtService), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder passwordEncoder() {
        return new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}