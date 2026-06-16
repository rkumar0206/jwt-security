package com.rksdev.security.api;

import com.rksdev.security.dto.SignUpRequest;

public interface PluggableUserRegistrationHandler {
    /**
     * Persist the newly registered user details into the local app storage.
     * @param request Validated request details with the PASSWORD ALREADY ENCODED/HASHED.
     * @return Any contextual response object (e.g., User ID, Success Message, User Record).
     */
    Object handleUserSignUp(SignUpRequest request);
}