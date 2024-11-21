package com.colak.springtutorial.config.authenticationsuccesshandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        String jsonResponse = determineMessage(authentication);

        if (response.isCommitted()) {
            return;
        }

        response.setContentType("application/json");
        response.getWriter().write(jsonResponse);
    }

    private String determineMessage(Authentication authentication) {
        String user = authentication.getName();

        if ("admin".equals(user)) {
            return """
            {
                "message": "Welcome admin! You have successfully logged in."
            }
            """;
        } else if ("user".equals(user)) {
            return """
            {
                "message": "Welcome user! You have successfully logged in."
            }
            """;
        }

        return "/";
    }

}
