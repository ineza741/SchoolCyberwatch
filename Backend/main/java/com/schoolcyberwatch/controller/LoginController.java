package com.schoolcyberwatch.controller;

import com.schoolcyberwatch.dto.LoginRequest;
import com.schoolcyberwatch.dto.LoginResponse;
import com.schoolcyberwatch.dto.RegisterRequest;
import com.schoolcyberwatch.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Authentication endpoint. Replaces the old mock login:
 * wrong credentials now return 401 with a JSON error message.
 */
@RestController
@RequestMapping("/api/auth")
public class LoginController {

    private final AuthService authService;

    public LoginController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        LoginResponse response = authService.login(loginRequest.getEmail(), loginRequest.getPassword());
        if (response == null) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", "Invalid email or password"));
        }
        return ResponseEntity.ok(response);
    }

    /**
     * Registers a new school ICT administrator account. On success the user
     * is signed in immediately (JWT returned, same shape as /login).
     * Validation/duplicate errors return 400 with a friendly message.
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        Object result = authService.register(
                request.getEmail(), request.getFullName(), request.getPassword());
        if (result instanceof LoginResponse response) {
            return ResponseEntity.status(201).body(response);
        }
        return ResponseEntity.badRequest().body(result);
    }
}
