package com.security.config.configuration.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record UserSignInRequestDto(
        @JsonProperty("username") String username,
        @JsonProperty("password") String password
) {
}
