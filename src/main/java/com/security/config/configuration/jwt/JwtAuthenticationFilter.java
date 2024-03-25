package com.security.config.configuration.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.config.configuration.auth.PrincipalDetails;
import com.security.config.configuration.dto.UserSignInRequestDto;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Date;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;
  private final AppProperties appProperties;

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
          throws AuthenticationException {

    ObjectMapper om = new ObjectMapper();
    UserSignInRequestDto loginRequestDto = null;
    try {
      loginRequestDto = om.readValue(request.getInputStream(), UserSignInRequestDto.class);
    } catch (Exception e) {
      e.printStackTrace();
    }
    assert loginRequestDto != null;
    System.out.println("JwtAuthenticationFilter - " + loginRequestDto.toString());
    UsernamePasswordAuthenticationToken authenticationToken =
            new UsernamePasswordAuthenticationToken(
                    loginRequestDto.username(),
                    loginRequestDto.password());

    return authenticationManager.authenticate(authenticationToken);
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                          Authentication authResult) {

    PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

    String jwtToken = JWT.create()
            .withSubject(principalDetails.getUsername())
            .withExpiresAt(new Date(System.currentTimeMillis() + appProperties.getEXPIRATION_TIME()))
            .withClaim("id", principalDetails.getUser().getId())
            .withClaim("username", principalDetails.getUser().getUsername())
            .sign(Algorithm.HMAC512(appProperties.getSECRET()));
    response.addHeader(appProperties.getTOKEN_PREFIX(), appProperties.getHEADER_STRING() + jwtToken);
  }
}
