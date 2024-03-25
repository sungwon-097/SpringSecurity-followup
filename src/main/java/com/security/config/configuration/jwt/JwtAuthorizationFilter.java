package com.security.config.configuration.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.config.configuration.auth.PrincipalDetails;
import com.security.config.domain.TestUser;
import com.security.config.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{

  private final UserRepository userRepository;
  private final AppProperties appProperties;
  private final ObjectMapper objectMapper = new ObjectMapper();

  public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository, AppProperties appProperties) {
    super(authenticationManager);
    this.userRepository = userRepository;
    this.appProperties = appProperties;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
          throws IOException, ServletException {
    String header = request.getHeader(appProperties.getTOKEN_PREFIX());
    if(header == null || !header.startsWith(appProperties.getHEADER_STRING())) {
      chain.doFilter(request, response);
      return;
    }
    String token = request.getHeader(appProperties.getTOKEN_PREFIX())
            .replace("Bearer ", "");
    System.out.println(token);
    try {
      String username = JWT.require(Algorithm
                      .HMAC512(appProperties.getSECRET()))
              .build()
              .verify(token)
              .getClaim("username").asString();

      if (username != null) {
        TestUser user = userRepository.findByUsername(username).orElseThrow(()->new Exception(""));
        PrincipalDetails principalDetails = new PrincipalDetails(user);
        Authentication authentication =
                new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
      }
    }catch (TokenExpiredException e){
      log.error("Token expired");
      setResponse(response, e, HttpServletResponse.SC_EXPECTATION_FAILED, "JWT : Token expired");
      return;

    }catch (SignatureVerificationException e){
      log.error("Signature not valid");
      setResponse(response, e, HttpServletResponse.SC_UNAUTHORIZED, "JWT : Signature not valid");
      return;

    }catch (UsernameNotFoundException e){
      log.error("User not found");
      setResponse(response, e, HttpServletResponse.SC_FORBIDDEN, "JWT : User not found");
      return;

    }catch (Exception e){
      log.error("exception");
      e.printStackTrace();
      setResponse(response, e, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "JWT : Undefined exception");
      return;

    }
    chain.doFilter(request, response);
  }

  private void setResponse(HttpServletResponse response, Exception exception, int status, String message) throws IOException {
    response.setStatus(status);
    response.setContentType("application/json");
    response.getWriter().write(objectMapper.writeValueAsString(status + message));
  }
}