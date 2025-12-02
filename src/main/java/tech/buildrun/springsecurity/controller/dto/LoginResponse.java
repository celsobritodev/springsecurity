package tech.buildrun.springsecurity.controller.dto;

public record LoginResponse(
        String accessToken,
        String refreshToken,
        long expiresIn
) {}