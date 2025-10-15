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
import jakarta.servlet.http.Cookie;

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

        // Debug log
        if (token != null) {
            System.out.println(
                    "🔐 SecurityFilter - Token found: " + token.substring(0, Math.min(10, token.length())) + "...");
        } else {
            System.out.println("🔐 SecurityFilter - No token found");
        }

        if (token != null) {
            var tokenData = tokenService.validateToken(token);
            // token invalid
            if (tokenData == null) {
                System.out.println("❌ SecurityFilter - Token validation failed");
                filterChain.doFilter(request, response);
                return;
            }

            var subject = tokenData.subject();
            if (subject == null || subject.isBlank()) {
                System.out.println("❌ SecurityFilter - Token subject is empty");
                filterChain.doFilter(request, response);
                return;
            }

            UserDetails user = userRepository.findByEmail(subject);
            if (user == null) {
                System.out.println("❌ SecurityFilter - User not found for email: " + subject);
                filterChain.doFilter(request, response);
                return;
            }

            // check persisted session
            var optSession = sessionRepository.findByToken(token);
            if (optSession.isEmpty()) {
                System.out.println("❌ SecurityFilter - Session not found in database");
                filterChain.doFilter(request, response);
                return;
            }

            Session session = optSession.get();
            if (session.isRevoked() || session.getExpiresAt().isBefore(java.time.Instant.now())) {
                System.out.println("❌ SecurityFilter - Session revoked or expired");
                filterChain.doFilter(request, response);
                return;
            }

            var authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println("✅ SecurityFilter - Authentication set for user: " + user.getUsername());
        }
        filterChain.doFilter(request, response);
    }

    private String recoverToken(HttpServletRequest request) {
        // Ưu tiên đọc từ Authorization header (backward compatibility)
        var authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            System.out.println("🔐 Token from Authorization header");
            return authHeader.substring(7);
        }

        // Đọc từ cookie
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("auth_token".equals(cookie.getName())) {
                    System.out.println("🔐 Token from auth_token cookie");
                    return cookie.getValue();
                }
            }
        }

        return null;
    }
}