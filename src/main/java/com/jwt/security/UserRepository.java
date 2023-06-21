package com.jwt.security;

import com.jwt.security.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {

    Optional<User>findByEmail(String email);

}
