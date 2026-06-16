package com.rksdev.security.service;

import com.rksdev.config.JwtProperties;
import com.rksdev.security.api.JwtCustomClaimsProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtService {

    private final JwtProperties jwtProperties;
    private final JwtCustomClaimsProvider customClaimsProvider;
    private final SecretKey verificationKey;

    public JwtService(JwtProperties jwtProperties, JwtCustomClaimsProvider customClaimsProvider) {
        this.jwtProperties = jwtProperties;
        this.customClaimsProvider = customClaimsProvider;
        // Pre-compute key using safe HMAC-SHA conversion from configured secret
        this.verificationKey = Keys.hmacShaKeyFor(jwtProperties.secret().getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(Authentication authentication) {
        Map<String, Object> claims = customClaimsProvider.getCustomClaims(authentication);
        return buildToken(authentication.getName(), authentication.getAuthorities(), jwtProperties.accessTokenExpirationMillis(), claims);
    }

    public String generateAccessToken(UserDetails userDetails) {
        return buildToken(userDetails.getUsername(), userDetails.getAuthorities(), jwtProperties.accessTokenExpirationMillis(), null);
    }

    private String buildToken(String username, Collection<? extends GrantedAuthority> authorities, long expiryMillis, Map<String, Object> customClaims) {
        List<String> roles = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        long now = System.currentTimeMillis();

        JwtBuilder jwtBuilder = Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuer(jwtProperties.issuer())
                .issuedAt(new Date())
                .expiration(new Date(now + expiryMillis))
                .signWith(verificationKey);

        if (customClaims != null) {
            jwtBuilder.claims(customClaims);
        }

        return jwtBuilder
                .compact();
    }

    /**
     * Parses and extracts all payload claims safely. Returns null if token is invalid or expired.
     */
    public Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(verificationKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            // Log this securely using your preferred logging library
            return null;
        }
    }

    public String extractUsername(Claims claims) {
        return claims.getSubject();
    }

    /**
     * Extracts authorities from the token payload and maps them back to SimpleGrantedAuthority objects.
     */
    @SuppressWarnings("unchecked")
    public Collection<? extends GrantedAuthority> extractAuthorities(Claims claims) {
        List<String> roles = claims.get("roles", List.class);
        if (roles == null) return List.of();

        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    public boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }
}