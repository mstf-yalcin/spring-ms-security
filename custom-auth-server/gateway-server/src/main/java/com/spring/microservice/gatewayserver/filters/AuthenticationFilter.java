package com.spring.microservice.gatewayserver.filters;


import com.spring.microservice.gatewayserver.exception.handler.ErrorResponseBuilder;
import com.spring.microservice.gatewayserver.util.JwtUtility;
import io.jsonwebtoken.Claims;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class AuthenticationFilter implements WebFilter {

    private final JwtUtility jwtUtil;
    private final ErrorResponseBuilder errorResponseBuilder;

    public AuthenticationFilter(JwtUtility jwtUtil, ErrorResponseBuilder errorResponseBuilder) {
        this.jwtUtil = jwtUtil;
        this.errorResponseBuilder = errorResponseBuilder;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            return chain.filter(exchange);
        }

        String authorizationHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }

        String token = authorizationHeader.substring(7);

        try {

            String username = jwtUtil.extractClaim(token, Claims::getSubject);
            List<String> roles = jwtUtil.extractClaim(token, claims -> claims.get("roles", List.class));

            List<SimpleGrantedAuthority> authorityList = roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(username, null, authorityList);

            return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
        } catch (Exception e) {

            return errorResponseBuilder.buildErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Invalid token.");
//            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
//            return exchange.getResponse().setComplete();
        }
    }
}





