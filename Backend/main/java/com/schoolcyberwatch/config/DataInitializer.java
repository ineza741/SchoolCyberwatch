package com.schoolcyberwatch.config;

import com.schoolcyberwatch.entity.Role;
import com.schoolcyberwatch.entity.User;
import com.schoolcyberwatch.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        if (userRepository.count() == 0) {
            User admin = new User("admin@school.edu.rw", passwordEncoder.encode("admin123"), Role.ADMIN);
            User staff = new User("staff@school.edu.rw", passwordEncoder.encode("staff123"), Role.ACADEMIC_STAFF);
            
            userRepository.save(admin);
            userRepository.save(staff);
            
            System.out.println("Initialized database with default users (admin@school.edu.rw & staff@school.edu.rw)");
        }
    }
}
