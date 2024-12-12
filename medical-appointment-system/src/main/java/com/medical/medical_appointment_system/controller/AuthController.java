package com.medical.medical_appointment_system.controller;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final ClientRegistration clientRegistration;

    @Autowired
    public AuthController(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistration = clientRegistrationRepository.findByRegistrationId("okta");
        logger.info("AuthController initialized with client registration: {}", clientRegistration.getClientName());
    }

    /**
     * Redirects users to the frontend.
     *
     * @return ResponseEntity with status 302 (FOUND) and redirect location.
     */
    @GetMapping("/redirect")
    public ResponseEntity<Void> redirectFrontend() {
        String frontendUrl = "http://localhost:3000";
        logger.info("Redirecting to frontend at {}", frontendUrl);
        return ResponseEntity.status(302)
                .header("Location", frontendUrl)
                .build();
    }

    /**
     * Returns the authentication status and user role.
     *
     * @param authentication Spring Security Authentication object.
     * @return ResponseEntity containing authentication status and role.
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getAuthStatus(Authentication authentication) {
        logger.debug("Received request for authentication status");

        Map<String, Object> response = new HashMap<>();
        if (authentication != null && authentication.isAuthenticated()) {
            String role = determineUserRole(authentication);
            logger.info("User authenticated. Username: {}, Role: {}", authentication.getName(), role);
            response.put("authenticated", true);
            response.put("role", role);
        } else {
            logger.warn("User unauthenticated. Defaulting role to PATIENT.");
            response.put("authenticated", false);
            response.put("role", "PATIENT");
        }

        return ResponseEntity.ok(response);
    }

    // The logout route
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, @AuthenticationPrincipal(expression = "idToken") OidcIdToken idToken) {
        // Build the logout details (end session endpoint and id token) to send to the client
        Map<String, String> logoutDetails = new HashMap<>();
        String logoutUrl = this.clientRegistration.getProviderDetails().getConfigurationMetadata().get("end_session_endpoint").toString();
        logoutDetails.put("logoutUrl", logoutUrl);
        logoutDetails.put("idToken", idToken.getTokenValue());
        // Log for debugging
        System.out.println("LogoutDetails, logoutURL: " + logoutUrl);
        System.out.println("LogoutDetails, idToken: " + idToken.getTokenValue());
        // Clear session
        if (request.getSession(false) != null) {
            request.getSession(false).invalidate();
        }
        return ResponseEntity.ok().body(logoutDetails);
    }

    /**
     * Determines the user's role based on their granted authorities.
     *
     * @param authentication Spring Security Authentication object.
     * @return String representing the user's role ("ADMIN" or "PATIENT").
     */
    private String determineUserRole(Authentication authentication) {
        logger.debug("Determining user role for authentication object: {}", authentication);
        String role = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(auth -> auth.startsWith("ROLE_"))
                .findFirst()
                .orElse("PATIENT");
        logger.info("Determined user role: {}", role);
        return role;
    }
}