package com.security.config.repository;

import com.security.config.domain.TestUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<TestUser, Long> {
    Optional<TestUser> findByUsername(String username);
}
