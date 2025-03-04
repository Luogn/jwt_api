package org.example.jwt_api.controller;

import org.example.jwt_api.model.User;
import org.example.jwt_api.repository.UserRepository;
import org.example.jwt_api.security.JwtAuthFilter;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final UserRepository userRepository;
    private final JwtAuthFilter jwtService;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserRepository userRepository, JwtAuthFilter jwtService, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticate(@RequestBody User loginRequest) {
        Optional<User> user = userRepository.findByUsername(loginRequest.getUsername());

        if (user.isPresent() && passwordEncoder.matches(loginRequest.getPassword(), user.get().getPassword())) {
            String token = jwtService.generateToken(user.get().getUsername(), user.get().getRole());
            return ResponseEntity.ok(token);
        }

        return ResponseEntity.status(401).body("Sai tên đăng nhập hoặc mật khẩu");
    }
}

