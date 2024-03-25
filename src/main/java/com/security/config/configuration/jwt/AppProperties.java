package com.security.config.configuration.jwt;

import lombok.Getter;
import org.springframework.stereotype.Component;

@Getter
@Component
public class AppProperties {
  private final String SECRET = "JWTSECRET!@#";
  private final int EXPIRATION_TIME = 360000;
  private final String TOKEN_PREFIX = "Authorization";
  private final String HEADER_STRING = "Bearer ";
}
