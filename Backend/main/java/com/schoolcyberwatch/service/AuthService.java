package com.schoolcyberwatch.service;

import com.schoolcyberwatch.model.User;
import com.schoolcyberwatch.repository.UserRepository;
import com.schoolcyberwatch.dto.LoginResponse;
import com.schoolcyberwatch.security.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * Real authentication: verifies the BCrypt password hash and issues a JWT.
 */
@Service
public class AuthService {

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    /** Returns a JWT on success, null when credentials are wrong. */
    public LoginResponse login(String email, String password) {
        if (email == null || email.isBlank() || password == null || password.isBlank()) {
            return null;
        }
        return userRepository.findByEmailIgnoreCase(email.trim())
                .filter(user -> passwordEncoder.matches(password, user.getPasswordHash()))
                .map(user -> new LoginResponse(
                        jwtService.generateToken(user.getEmail(), user.getRole()),
                        user.getEmail(),
                        user.getFullName()))
                .orElse(null);
    }

    /**
     * Registers a new ICT administrator account (BCrypt-hashed password).
     * Returns the login-style response on success, or an error message
     * starting with "Already registered" / "Invalid" when validation fails.
     */
    public Object register(String email, String fullName, String password) {
        if (email == null || email.isBlank() || fullName == null || fullName.isBlank()
                || password == null || password.isBlank()) {
            return Map.of("error", "All fields are required");
        }
        String normalized = email.trim().toLowerCase();
        if (!EMAIL_PATTERN.matcher(normalized).matches()) {
            return Map.of("error", "Invalid email address");
        }
        String trimmedName = fullName.trim();
        if (trimmedName.length() < 3 || trimmedName.length() > 120) {
            return Map.of("error", "Full name must be 3-120 characters");
        }
        if (password.length() < 8) {
            return Map.of("error", "Password must be at least 8 characters");
        }
        if (userRepository.findByEmailIgnoreCase(normalized).isPresent()) {
            return Map.of("error", "Already registered: an account with this email exists");
        }
        User user = new User(normalized, passwordEncoder.encode(password), trimmedName);
        user.setRole("ADMIN");
        userRepository.save(user);
        return new LoginResponse(
                jwtService.generateToken(user.getEmail(), user.getRole()),
                user.getEmail(),
                user.getFullName());
    }

    /** Used by the startup bootstrap to create the first ICT administrator. */
    public void createAdminIfMissing(String email, String password) {
        String normalized = email.trim().toLowerCase();
        if (userRepository.findByEmailIgnoreCase(normalized).isPresent()) {
            return;
        }
        User admin = new User(normalized, passwordEncoder.encode(password), "School ICT Administrator");
        admin.setRole("ADMIN");
        userRepository.save(admin);
    }

    public User getByEmail(String email) {
        return userRepository.findByEmailIgnoreCase(email).orElse(null);
    }
}
