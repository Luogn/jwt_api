package org.example.jwt_api.service;


import org.example.jwt_api.model.User;
import org.example.jwt_api.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Tạo người dùng mới với mật khẩu được mã hóa
    public User createUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword())); // Mã hóa mật khẩu
        return userRepository.save(user);
    }

    // Tìm người dùng theo username
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}
