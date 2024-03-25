package com.security.config.configuration.dto;

public record UserSignUpRequestDto(
        String username,
        String password
        // 추가 작성
) {
}
