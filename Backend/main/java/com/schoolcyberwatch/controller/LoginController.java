package com.schoolcyberwatch.controller;

import com.schoolcyberwatch.dto.LoginRequest;
import com.schoolcyberwatch.dto.LoginResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class LoginController {

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        // Mock authentication logic matching frontend expectations
        if (loginRequest.getEmail() != null && !loginRequest.getEmail().isEmpty()) {
            return ResponseEntity.ok(new LoginResponse("mock-jwt-token-123"));
        }
        return ResponseEntity.badRequest().build();
    }
}
