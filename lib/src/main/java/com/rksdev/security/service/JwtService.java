package com.rksdev.security.service;

import com.rksdev.config.JwtProperties;
import com.rksdev.security.api.JwtCustomClaimsProvider;
import com.rksdev.security.api.IdentifiableUser;
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
import java.util.HashMap;
import java.util.stream.Collectors;

public class JwtService {

    private final JwtProperties jwtProperties;
    private final JwtCustomClaimsProvider customClaimsProvider;
    private final SecretKey verificationKey;

    public JwtService(JwtProperties jwtProperties, JwtCustomClaimsProvider customClaimsProvider) {
        this.jwtProperties = jwtProperties;
        this.customClaimsProvider = customClaimsProvider;
        this.verificationKey = Keys.hmacShaKeyFor(jwtProperties.secret().getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(Authentication authentication) {
        Map<String, Object> claims = customClaimsProvider.getCustomClaims(authentication);
        if (claims == null) claims = new HashMap<>();

        String subjectId = resolveSubjectId(authentication.getPrincipal(), authentication.getName());

        // Retain readable username in claims if subject becomes the numeric ID
        claims.putIfAbsent("username", authentication.getName());

        return buildToken(subjectId, authentication.getAuthorities(), jwtProperties.accessTokenExpirationMillis(), claims);
    }

    public String generateAccessToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        String subjectId = resolveSubjectId(userDetails, userDetails.getUsername());

        claims.put("username", userDetails.getUsername());
        claims.putIfAbsent("isEnabled", userDetails.isEnabled());

        return buildToken(subjectId, userDetails.getAuthorities(), jwtProperties.accessTokenExpirationMillis(), claims);
    }

    private String buildToken(String subjectId, Collection<? extends GrantedAuthority> authorities, long expiryMillis, Map<String, Object> customClaims) {
        List<String> roles = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        long now = System.currentTimeMillis();

        JwtBuilder jwtBuilder = Jwts.builder()
                .subject(subjectId) // This is now guaranteed to be the stringified user ID
                .claim("roles", roles)
                .issuer(jwtProperties.issuer())
                .issuedAt(new Date())
                .expiration(new Date(now + expiryMillis))
                .signWith(verificationKey);

        if (customClaims != null && !customClaims.isEmpty()) {
            jwtBuilder.claims(customClaims);
        }

        return jwtBuilder.compact();
    }

    /**
     * Determines whether to use the custom numeric User ID or fallback to standard name string.
     */
    private String resolveSubjectId(Object principal, String fallbackName) {
        if (principal instanceof IdentifiableUser) {
            return String.valueOf(((IdentifiableUser) principal).getUserId());
        }
        return fallbackName;
    }

    public Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(verificationKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtException(e.getMessage());
        }
    }

    public String extractSubject(Claims claims) {
        return claims.getSubject();
    }

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