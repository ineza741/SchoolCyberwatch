package com.schoolcyberwatch.service;

import com.schoolcyberwatch.dto.LoginRequest;
import com.schoolcyberwatch.dto.LoginResponse;
import com.schoolcyberwatch.entity.User;
import com.schoolcyberwatch.repository.UserRepository;
import com.schoolcyberwatch.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    public LoginResponse authenticate(LoginRequest loginRequest) {
        Optional<User> optionalUser = userRepository.findByEmail(loginRequest.getEmail());
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            if (passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
                String token = jwtUtil.generateToken(user.getEmail(), user.getRole().name());
                return new LoginResponse(token);
            }
        }
        return null;
    }
}
