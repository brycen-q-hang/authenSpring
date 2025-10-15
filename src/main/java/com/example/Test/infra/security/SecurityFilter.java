package com.example.Test.infra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.Test.repositories.UserRepository;
import com.example.Test.repositories.SessionRepository;
import com.example.Test.intities.sessions.Session;

import java.io.IOException;

@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private SessionRepository sessionRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        var token = this.recoverToken(request);
        if (token != null) {
            var tokenData = tokenService.validateToken(token);
            // token invalid
            if (tokenData == null) {
                filterChain.doFilter(request, response);
                return;
            }

            var subject = tokenData.subject();
            if (subject == null || subject.isBlank()) {
                filterChain.doFilter(request, response);
                return;
            }

            UserDetails user = userRepository.findByEmail(subject);
            if (user == null) {
                filterChain.doFilter(request, response);
                return;
            }

            // check persisted session
            var optSession = sessionRepository.findByToken(token);
            if (optSession.isEmpty()) {
                filterChain.doFilter(request, response);
                return;
            }

            Session session = optSession.get();
            if (session.isRevoked() || session.getExpiresAt().isBefore(java.time.Instant.now())) {
                filterChain.doFilter(request, response);
                return;
            }

            var authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }

    private String recoverToken(HttpServletRequest request) {
        var authHeader = request.getHeader("Authorization");
        if (authHeader == null)
            return null;
        if (!authHeader.startsWith("Bearer "))
            return null;
        return authHeader.substring(7);
    }
}
