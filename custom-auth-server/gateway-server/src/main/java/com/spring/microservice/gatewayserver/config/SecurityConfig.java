package com.spring.microservice.gatewayserver.config;

import com.spring.microservice.gatewayserver.exception.handler.CustomAccessDeniedHandler;
import com.spring.microservice.gatewayserver.exception.handler.CustomAuthenticationEntryPoint;
import com.spring.microservice.gatewayserver.filters.AuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http.authorizeExchange(auth -> {
                    auth.pathMatchers(HttpMethod.GET).permitAll()
                            .pathMatchers("/gateway/accounts/**").hasRole("ACCOUNTS")
                            .pathMatchers("/gateway/cards/**").hasRole("CARDS")
                            .pathMatchers("/gateway/loans/**").hasRole("LOANS");
                })
                .exceptionHandling(exceptionHandler -> {
                    exceptionHandler.accessDeniedHandler(customAccessDeniedHandler)
                            .authenticationEntryPoint(customAuthenticationEntryPoint);
                })
                .addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION);
        http.csrf(ServerHttpSecurity.CsrfSpec::disable);
        return http.build();
    }

    private final AuthenticationFilter authenticationFilter;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;

    public SecurityConfig(AuthenticationFilter authenticationFilter, CustomAuthenticationEntryPoint customAuthenticationEntryPoint, CustomAccessDeniedHandler customAccessDeniedHandler) {
        this.authenticationFilter = authenticationFilter;
        this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
        this.customAccessDeniedHandler = customAccessDeniedHandler;
    }


}
