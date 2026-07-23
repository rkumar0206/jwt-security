package com.rksdev.security.controller;

import com.rksdev.config.JwtProperties;
import com.rksdev.security.api.PluggablePasswordResetHandler;
import com.rksdev.security.api.PluggableRefreshTokenHandler;
import com.rksdev.security.api.PluggableUserRegistrationHandler;
import com.rksdev.security.dto.*;
import com.rksdev.security.service.JwtService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
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
     * 2. USER LOGIN FLOW (HttpOnly Cookies Setup)
     * ========================================== */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        String accessToken = jwtService.generateAccessToken(authentication);

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();

        ResponseCookie accessCookie = ResponseCookie.from("access_token", accessToken)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(jwtProperties.accessTokenExpirationMillis() / 1000)
                .build();
        headers.add(HttpHeaders.SET_COOKIE, accessCookie.toString());

        if (refreshTokenHandler != null) {
            String refreshToken = UUID.randomUUID().toString();
            Instant expiry = Instant.now().plusMillis(jwtProperties.refreshTokenExpirationMillis());
            refreshTokenHandler.saveRefreshToken(authentication.getName(), refreshToken, expiry);

            ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", refreshToken)
                    .httpOnly(true)
                    .secure(false)
                    .sameSite("Lax")
                    .path("/")
                    .maxAge(jwtProperties.refreshTokenExpirationMillis() / 1000)
                    .build();
            headers.add(HttpHeaders.SET_COOKIE, refreshCookie.toString());
        }

        return new ResponseEntity<>(
                Map.of("username", authentication.getName(), "message", "Login secure and complete."),
                headers,
                HttpStatus.OK
        );
    }

    /* ==========================================
     * 3. TOKEN REFRESH ROTATION FLOW (Reads from Cookie)
     * ========================================== */
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@CookieValue(name = "refresh_token", required = false) String refreshToken) {
        if (refreshTokenHandler == null || userDetailsService == null) {
            return buildFeatureNotImplementedResponse("Token Refresh Rotation");
        }

        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Missing required refresh validation token context."));
        }

        return refreshTokenHandler.getUsernameIfValid(refreshToken)
                .map(username -> {
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    if (!userDetails.isEnabled()) {
                        throw new DisabledException("User is disabled");
                    }

                    String newAccessToken = jwtService.generateAccessToken(userDetails);

                    // Drop an updated short-lived access cookie back into the cluster browser
                    ResponseCookie updatedAccessCookie = ResponseCookie.from("access_token", newAccessToken)
                            .httpOnly(true)
                            .secure(jwtProperties.secureCookies())
                            .sameSite("Lax")
                            .path("/")
                            .maxAge(jwtProperties.accessTokenExpirationMillis() / 1000)
                            .build();

                    return ResponseEntity.ok()
                            .header(HttpHeaders.SET_COOKIE, updatedAccessCookie.toString())
                            .body(Map.of("message", "Session continuity verification verified."));
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Refresh token is invalid or expired.")));
    }

    /* ==========================================
     * 6. SECURE LOGOUT FLOW (Clear Client Cookies)
     * ========================================== */
    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();

        ResponseCookie deleteAccessCookie = ResponseCookie.from("access_token", "")
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(0)
                .build();

        ResponseCookie deleteRefreshCookie = ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(0)
                .build();

        headers.add(HttpHeaders.SET_COOKIE, deleteAccessCookie.toString());
        headers.add(HttpHeaders.SET_COOKIE, deleteRefreshCookie.toString());

        return new ResponseEntity<>(Map.of("message", "Logged out cleanly."), headers, HttpStatus.OK);
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

    private ResponseEntity<Map<String, String>> buildFeatureNotImplementedResponse(String featureName) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).body(Map.of(
                "error", "Feature Not Implemented",
                "message", featureName + " capabilities are not activated on this cluster instance. Ensure the correct Handler bean is registered."
        ));
    }
}