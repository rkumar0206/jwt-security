package com.rksdev.security.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Data Transfer Object representing a request to initiate a password reset flow.
 */
public record ForgotPasswordRequest(
        @NotBlank(message = "Email address is required")
        @Email(message = "Please provide a valid email format")
        String email
) {}