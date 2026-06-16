package com.rksdev.security.controller;

import com.rksdev.config.JwtProperties;
import com.rksdev.security.api.PluggablePasswordResetHandler;
import com.rksdev.security.api.PluggableRefreshTokenHandler;
import com.rksdev.security.api.PluggableUserRegistrationHandler;
import com.rksdev.security.dto.*;
import com.rksdev.security.service.JwtService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
public class PluggableAuthController {

    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final AuthenticationManager authenticationManager;

    // Optional SPI implementations provided selectively by host applications
    private final PluggableUserRegistrationHandler registrationHandler;
    private final PluggableRefreshTokenHandler refreshTokenHandler;
    private final PluggablePasswordResetHandler passwordResetHandler;
    private final UserDetailsService userDetailsService;
    private final org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;

    public PluggableAuthController(
            JwtService jwtService,
            JwtProperties jwtProperties,
            AuthenticationManager authenticationManager,
            @Autowired(required = false) PluggableUserRegistrationHandler registrationHandler,
            @Autowired(required = false) PluggableRefreshTokenHandler refreshTokenHandler,
            @Autowired(required = false) PluggablePasswordResetHandler passwordResetHandler,
            @Autowired(required = false) UserDetailsService userDetailsService,
            org.springframework.security.crypto.password.PasswordEncoder passwordEncoder) {
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
        this.authenticationManager = authenticationManager;
        this.registrationHandler = registrationHandler;
        this.refreshTokenHandler = refreshTokenHandler;
        this.passwordResetHandler = passwordResetHandler;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    /* ==========================================
     * 1. USER SIGN-UP FLOW
     * ========================================== */
    @PostMapping("/signup")
    public ResponseEntity<?> signUpUser(@Valid @RequestBody SignUpRequest request) {
        if (registrationHandler == null) {
            return buildFeatureNotImplementedResponse("User Registration");
        }

        String hashedPwd = passwordEncoder.encode(request.password());
        SignUpRequest secureRequest = new SignUpRequest(request.username(), request.email(), hashedPwd);

        Object executionResult = registrationHandler.handleUserSignUp(secureRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(executionResult);
    }

    /* ==========================================
     * 2. USER LOGIN FLOW (Access + Refresh)
     * ========================================== */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        String accessToken = jwtService.generateAccessToken(authentication);

        // If the host app handles refresh token storage, issue one alongside the access token
        if (refreshTokenHandler != null) {
            String refreshToken = UUID.randomUUID().toString();
            Instant expiry = Instant.now().plusMillis(jwtProperties.refreshTokenExpirationMillis());
            refreshTokenHandler.saveRefreshToken(authentication.getName(), refreshToken, expiry);

            return ResponseEntity.ok(new LoginResponse(accessToken, refreshToken, authentication.getName()));
        }

        // Fallback for stateless services that only use access tokens
        return ResponseEntity.ok(new LoginResponse(accessToken, null, authentication.getName()));
    }

    /* ==========================================
     * 3. TOKEN REFRESH ROTATION FLOW
     * ========================================== */
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@Valid @RequestBody TokenRefreshRequest request) {
        if (refreshTokenHandler == null || userDetailsService == null) {
            return buildFeatureNotImplementedResponse("Token Refresh Rotation");
        }

        return refreshTokenHandler.getUsernameIfValid(request.refreshToken())
                .map(username -> {
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    String newAccessToken = jwtService.generateAccessToken(userDetails);
                    return ResponseEntity.ok(Map.of(
                            "accessToken", newAccessToken,
                            "refreshToken", request.refreshToken()
                    ));
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Refresh token is invalid or expired.")));
    }

    /* ==========================================
     * 4. FORGOT PASSWORD REQUEST FLOW
     * ========================================== */
    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        if (passwordResetHandler == null) {
            return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                    .body(Map.of("error", "Password Reset feature is not enabled on this service."));
        }

        String secureToken = UUID.randomUUID().toString();
        passwordResetHandler.handleResetRequested(request.email(), secureToken);

        return ResponseEntity.ok(Map.of("message", "If that account exists, a secure reset link has been dispatched."));
    }

    /* ==========================================
     * 5. RESET PASSWORD ACTION FLOW
     * ========================================== */
    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        if (passwordResetHandler == null) {
            return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                    .body(Map.of("error", "Password Reset feature is not enabled on this service."));
        }

        String hashedNewPassword = passwordEncoder.encode(request.newPassword());
        boolean isSuccess = passwordResetHandler.handlePasswordReset(request.token(), hashedNewPassword);

        if (!isSuccess) {
            return ResponseEntity.badRequest().body(Map.of("error", "The password reset token is invalid or has expired."));
        }

        return ResponseEntity.ok(Map.of("message", "Password structural updates complete. You may now log in."));
    }

    /* ==========================================
     * HELPER: REUSABLE DEGRADATION RESPONSE
     * ========================================== */
    private ResponseEntity<Map<String, String>> buildFeatureNotImplementedResponse(String featureName) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).body(Map.of(
                "error", "Feature Not Implemented",
                "message", featureName + " capabilities are not activated on this cluster instance. Ensure the correct Handler bean is registered."
        ));
    }
}