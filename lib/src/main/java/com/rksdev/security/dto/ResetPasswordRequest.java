package com.rksdev.security.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Data Transfer Object representing the final password submission payload.
 */
public record ResetPasswordRequest(
        @NotBlank(message = "Security reset token is required")
        String token,

        @NotBlank(message = "New password cannot be blank")
        @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters long")
        // NOTE: If you have your custom password rule annotation (e.g., @ValidPassword),
        // feel free to place it right here to enforce strict character constraints globally!
        String newPassword
) {}