package com.rksdev.security.api;

import java.time.Instant;
import java.util.Optional;

public interface PluggableRefreshTokenHandler {
    /** Stores a securely generated refresh token linked to a user. */
    void saveRefreshToken(String username, String token, Instant expiryDate);

    /** Resolves the associated username if the token exists and hasn't expired. */
    Optional<String> getUsernameIfValid(String token);

    /** Invalidates a token (used during logouts). */
    void revokeToken(String token);
}