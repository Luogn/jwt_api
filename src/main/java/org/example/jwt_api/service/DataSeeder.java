package org.example.jwt_api.service;

import org.example.jwt_api.model.User;
import org.example.jwt_api.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;


@Component
public class DataSeeder implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataSeeder(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        if (userRepository.count() == 0) { // Nếu DB chưa có user nào
            User admin = new User();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("123456")); // Mật khẩu phải mã hóa
            admin.setRole("ADMIN");
            userRepository.save(admin);

            System.out.println("✅ Đã tạo tài khoản ADMIN: admin / 123456");
        }
    }
}

