package com.rksdev.security.filter;

import com.rksdev.security.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    /**
     * Define paths that should skip this filter entirely (e.g., Auth Endpoints).
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.startsWith("/api/v1/auth") || path.startsWith("/auth");
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String jwt = extractTokenFromCookie(request);

        // Scenario 1: No Token present
        // Do NOT return 401 manually here. Simply proceed down the filter chain without
        // setting the SecurityContext. Spring Security's SecurityFilterChain will check
        // if the request path is permitAll() or requires authentication.
        if (jwt == null || jwt.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            final Claims claims = jwtService.extractAllClaims(jwt);

            if (claims != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                if (!jwtService.isTokenExpired(claims)) {

                    Boolean isEnabled = claims.get("isEnabled", Boolean.class);
                    if (Boolean.FALSE.equals(isEnabled)) {
                        throw new DisabledException("User account is disabled");
                    }

                    String userIdStr = jwtService.extractSubject(claims);
                    Collection<? extends GrantedAuthority> authorities = jwtService.extractAuthorities(claims);

                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userIdStr, null, authorities
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (JwtException | AuthenticationException e) {
            // Guarantee thread safety by clearing context on invalid token or disabled account
            SecurityContextHolder.clearContext();
        }

        // Pass control to the next filter in the chain
        filterChain.doFilter(request, response);
    }

    /**
     * Helper method to extract token from HttpOnly cookies with optional Header fallback.
     */
    private String extractTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("access_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        // Fallback to Bearer token header if cookie is missing (useful for Swagger/Postman testing)
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        return null;
    }
}