package com.rksdev.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Collections;
import java.util.List;

@ConfigurationProperties(prefix = "jwt.properties")
public record JwtProperties(
        boolean enabled,
        String secret,
        String issuer,
        long accessTokenExpirationMillis,  // e.g., 900000 (15 mins)
        long refreshTokenExpirationMillis, // e.g., 604800000 (7 days)
        List<String> publicEndpoints,
        List<RoleMapping> roleMappings
) {

    public JwtProperties {
        if (publicEndpoints == null) publicEndpoints = Collections.emptyList();
        if (roleMappings == null) roleMappings = Collections.emptyList();
    }

    public record RoleMapping(String pattern, List<String> roles) {
    }
}
