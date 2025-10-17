package com.example.Test.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.Test.infra.security.TokenService;
import com.example.Test.intities.users.User;
import com.example.Test.intities.users.dtos.AuthenticationDTO;
import com.example.Test.intities.users.dtos.LoginResponseDTO;
import com.example.Test.intities.users.dtos.RegisterDTO;
import com.example.Test.repositories.UserRepository;

import jakarta.servlet.http.HttpServletResponse;

import com.example.Test.repositories.SessionRepository;
import com.example.Test.intities.sessions.Session;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping(value = "/auth", produces = { "application/json" })
public class AuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private TokenService tokenService;
    @Autowired
    private SessionRepository sessionRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Authenticates user login.
     *
     * @param data Object containing user credentials
     * @return ResponseEntity containing authentication token
     */
    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<LoginResponseDTO> login(@RequestBody AuthenticationDTO data, HttpServletResponse response) {
        var credentials = new UsernamePasswordAuthenticationToken(data.email(),
                data.password());
        org.springframework.security.core.Authentication auth;
        try {
            auth = this.authenticationManager.authenticate(credentials);
        } catch (org.springframework.security.core.AuthenticationException ex) {
            // Log the exception to help debugging and return 401 to client
            System.err.println("Authentication failed for user=" + data.email() + ": " +
                    ex.getMessage());
            return ResponseEntity.status(401).build();
        }

        var token = tokenService.generateToken((User) auth.getPrincipal());

        // persist session in DB
        var tokenData = tokenService.validateToken(token);
        var user = (User) auth.getPrincipal();
        if (tokenData != null) {
            Session session = new Session(token, user, java.time.Instant.now(),
                    tokenData.expiresAt(), false);
            sessionRepository.save(session);
        }

        // Create cookie with token
        Cookie authCookie = new Cookie("auth_token", token);
        authCookie.setHttpOnly(true); // Anti-XSS - Unreadable JavaScript
        authCookie.setSecure(false); // Set true if using HTTPS (development: false)
        authCookie.setPath("/"); // Available for all paths
        authCookie.setMaxAge(60 * 60 * 24); // 24 hours

        response.addCookie(authCookie);
        System.out.println("Token saved to cookie: " + token.substring(0, Math.min(20, token.length())) + "...");

        LoginResponseDTO loginResponse = new LoginResponseDTO(token);
        return ResponseEntity.ok(loginResponse);
    }

    /**
     * Registers a new user.
     *
     * @param data Object containing user registration data
     * @return ResponseEntity indicating success or failure of registration
     */
    @PostMapping(value = "/register", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> register(@RequestBody RegisterDTO data) {
        if (this.userRepository.findByEmail(data.email()) != null)
            return ResponseEntity.badRequest().build();
        String encryptedPassword = passwordEncoder.encode(data.password());
        User user = new User(data.name(), data.email(), encryptedPassword, data.role());

        this.userRepository.save(user);

        return ResponseEntity.ok().build();
    }

    @PostMapping(value = "/logout")
    public ResponseEntity<?> logout(
            @CookieValue(name = "auth_token", required = false) String token,
            HttpServletRequest request,
            HttpServletResponse response) {

        System.out.println("=== LOGOUT API CALLED ===");
        if (token == null) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("auth_token".equals(cookie.getName())) {
                        token = cookie.getValue();
                        break;
                    }
                }
            }
        }

        System.out.println("Token from cookie: "
                + (token != null ? token.substring(0, Math.min(10, token.length())) + "..." : "NULL"));

        if (token == null) {
            System.out.println(" No authentication token found in cookies");
            return ResponseEntity.status(401).body("No authentication token found");
        }

        try {
            var opt = sessionRepository.findByToken(token);
            if (opt.isPresent()) {
                var session = opt.get();
                session.setRevoked(true);
                sessionRepository.save(session);
                System.out.println("Logout successful for user: " + session.getUser().getEmail());
            } else {
                System.out.println(" Session not found for token");
            }

            // Delete COOKIE
            Cookie authCookie = new Cookie("auth_token", null);
            authCookie.setHttpOnly(true);
            authCookie.setSecure(false);
            authCookie.setPath("/");
            authCookie.setMaxAge(0);
            response.addCookie(authCookie);

            System.out.println("Cookie cleared successfully");

            return ResponseEntity.ok().body("Logged out successfully");
        } catch (Exception e) {
            System.err.println(" Logout error: " + e.getMessage());
            return ResponseEntity.status(500).body("Logout failed");
        }
    }
}
