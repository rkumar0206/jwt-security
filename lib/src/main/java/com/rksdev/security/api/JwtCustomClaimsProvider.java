package com.rksdev.security.api;

import org.springframework.security.core.Authentication;
import java.util.Map;

@FunctionalInterface
public interface JwtCustomClaimsProvider {
    /**
     * Dynamically resolve custom claims to inject into the JWT payload.
     * @param authentication The current authenticated user context.
     * @return A map of claim keys and values.
     */
    Map<String, Object> getCustomClaims(Authentication authentication);
}