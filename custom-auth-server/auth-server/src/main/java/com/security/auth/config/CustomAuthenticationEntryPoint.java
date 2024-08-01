package com.security.auth.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final HandlerExceptionResolver handlerExceptionResolver;

    public CustomAuthenticationEntryPoint(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver handlerExceptionResolver) {
        this.handlerExceptionResolver = handlerExceptionResolver;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        handlerExceptionResolver.resolveException(request, response, null, authException);

//        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//
//        // Create a JSON response body
//        Map<String, Object> body = new HashMap<>();
//        ArrayList<String> errors = new ArrayList<>();
//        errors.add(authException.getMessage());
//
//        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
//        body.put("errors", errors);
//
//        // Convert the response body to JSON and write it to the response
//        response.setContentType("application/json");
//        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
    }
}
