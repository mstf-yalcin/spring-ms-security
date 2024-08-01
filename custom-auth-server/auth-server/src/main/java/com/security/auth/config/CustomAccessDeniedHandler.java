package com.security.auth.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private final HandlerExceptionResolver handlerExceptionResolver;

    public CustomAccessDeniedHandler(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver handlerExceptionResolver) {
        this.handlerExceptionResolver = handlerExceptionResolver;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        handlerExceptionResolver.resolveException(request, response, null, accessDeniedException);

//        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
//
//        // Create a JSON response body
//        Map<String, Object> body = new HashMap<>();
//        ArrayList<String> errors = new ArrayList<>();
//        errors.add(accessDeniedException.getMessage());
//
//        body.put("status", HttpServletResponse.SC_FORBIDDEN);
//        body.put("errors", errors);
//
//        // Convert the response body to JSON and write it to the response
//        response.setContentType("application/json");
//        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
//        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden: You don't have permission to access this resource.");
    }
}
