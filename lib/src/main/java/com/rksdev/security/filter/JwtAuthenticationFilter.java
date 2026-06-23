package com.rksdev.security.filter;

import com.rksdev.security.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Scenario 1: No Token - Pass along to next filter and exit immediately
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);

        try {
            final Claims claims = jwtService.extractAllClaims(jwt);

            if (claims != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                if (!jwtService.isTokenExpired(claims)) {
                    // Extracted string is now explicitly our numerical subject ("4821")
                    String userIdStr = jwtService.extractSubject(claims);
                    Collection<? extends GrantedAuthority> authorities = jwtService.extractAuthorities(claims);

                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userIdStr, null, authorities
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }

            // Scenario 2: Token is completely valid - Pass down the chain to controllers
            filterChain.doFilter(request, response);

        } catch (JwtException e) {

            // Scenario 3: Token validation failed - Short-circuit right here!
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");

            String jsonErrorResponse = String.format(
                    "{\"status\": 401, \"error\": \"Unauthorized\", \"message\": \"%s\"}",
                    e.getMessage() != null ? e.getMessage().replace("\"", "\\\"") : "Token validation failed"
            );

            response.getWriter().write(jsonErrorResponse);
            response.getWriter().flush();

            // Explicitly return to ensure no other code or filter logic runs on this thread
            return;
        }
    }
}