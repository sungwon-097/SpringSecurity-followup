package com.security.config.configuration;

import com.security.config.configuration.auth.PrincipalDetailsService;
import com.security.config.configuration.jwt.*;
import com.security.config.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final PrincipalDetailsService principalDetailsService;
  private final JwtAuthenticationEntryPoint entryPoint;
  private final AppProperties properties;
  private final UserRepository repository;
  private final WebConfig webConfig;


  @Bean
  public BCryptPasswordEncoder encoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public AuthenticationManager getAuthenticationManager(HttpSecurity http) throws Exception {
    AuthenticationManagerBuilder sharedObject = http.getSharedObject(AuthenticationManagerBuilder.class);

    sharedObject.userDetailsService(this.principalDetailsService);

    return sharedObject.build();
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    AuthenticationManager authenticationManager = this.getAuthenticationManager(http);
    http.authenticationManager(authenticationManager)
        .csrf(AbstractHttpConfigurer::disable)
        .cors(Customizer.withDefaults())
        .addFilterBefore(new TenantFilter(), UsernamePasswordAuthenticationFilter.class)
        .addFilterBefore(new JwtAuthenticationFilter(authenticationManager, properties), UsernamePasswordAuthenticationFilter.class)
        .addFilterBefore(new JwtAuthorizationFilter(authenticationManager, repository, properties), UsernamePasswordAuthenticationFilter.class)
        .addFilter(webConfig.corsFilter())
        .httpBasic(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/signin").permitAll()
                .requestMatchers("/signup").permitAll()
                .requestMatchers("/swagger-ui/**").permitAll()
                .requestMatchers("/v3/api-docs/**").permitAll()
                .requestMatchers("/swagger-resources/**").permitAll()
                .anyRequest().authenticated()
        )
        .exceptionHandling(e -> e.authenticationEntryPoint(entryPoint))
        .httpBasic(Customizer.withDefaults());
    return http.build();
  }
}