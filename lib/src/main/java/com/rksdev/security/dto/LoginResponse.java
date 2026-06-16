package com.rksdev.security.dto;

public record LoginResponse(
        String accessToken,
        String refreshToken,
        String username
) {}