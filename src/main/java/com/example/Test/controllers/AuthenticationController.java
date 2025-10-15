package com.example.Test.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestHeader;
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
import com.example.Test.repositories.SessionRepository;
import com.example.Test.intities.sessions.Session;

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
    public ResponseEntity<LoginResponseDTO> login(@RequestBody AuthenticationDTO data) {
        var credentials = new UsernamePasswordAuthenticationToken(data.email(), data.password());
        org.springframework.security.core.Authentication auth;
        try {
            auth = this.authenticationManager.authenticate(credentials);
        } catch (org.springframework.security.core.AuthenticationException ex) {
            // Log the exception to help debugging and return 401 to client
            System.err.println("Authentication failed for user=" + data.email() + ": " + ex.getMessage());
            return ResponseEntity.status(401).build();
        }

        var token = tokenService.generateToken((User) auth.getPrincipal());

        // persist session in DB
        var tokenData = tokenService.validateToken(token);
        var user = (User) auth.getPrincipal();
        if (tokenData != null) {
            Session session = new Session(token, user, java.time.Instant.now(), tokenData.expiresAt(), false);
            sessionRepository.save(session);
        }

        return ResponseEntity.ok(new LoginResponseDTO(token));
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
    public ResponseEntity<?> logout(@RequestHeader(name = "Authorization", required = false) String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer "))
            return ResponseEntity.badRequest().build();

        String token = authorization.replace("Bearer ", "");
        var opt = sessionRepository.findByToken(token);
        if (opt.isPresent()) {
            var session = opt.get();
            session.setRevoked(true);
            sessionRepository.save(session);
        }

        return ResponseEntity.ok().build();
    }
}
