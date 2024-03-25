package com.security.config.controller;

import com.security.config.configuration.dto.UserSignUpRequestDto;
import com.security.config.domain.TestUser;
import com.security.config.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class Controller {

    private final UserRepository repository;
    private final BCryptPasswordEncoder encoder;

    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@RequestBody UserSignUpRequestDto dto){
        try {

            var user = repository.save(TestUser.builder()
                    .username(dto.username())
                    .password(encoder.encode(dto.password()))
                    .roles("ROLE_USER")
                    .build());

            return ResponseEntity.status(HttpStatus.CREATED).body(user);

        }catch (RuntimeException e){
            throw new RuntimeException(e.getMessage());
        }
    }

    @GetMapping("/test-endpoint")
    public ResponseEntity<?> testEndpoint(){
        return ResponseEntity.status(HttpStatus.OK).body("SUCCESS");
    }
}
