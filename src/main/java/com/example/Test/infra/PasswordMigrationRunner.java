package com.example.Test.infra;

import com.example.Test.intities.users.User;
import com.example.Test.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class PasswordMigrationRunner implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${app.migrate-encode-plaintext:false}")
    private boolean migrateEncodePlaintext;

    @Override
    public void run(String... args) throws Exception {
        if (!migrateEncodePlaintext) {
            return;
        }

        List<User> users = userRepository.findAll();
        for (User u : users) {
            String stored = u.getPassword();
            if (stored == null) continue;

            // BCrypt hashes usually start with $2a$ or $2b$ or $2y$
            if (!stored.startsWith("$2a$") && !stored.startsWith("$2b$") && !stored.startsWith("$2y$")) {
                // assume plaintext (ONLY use in trusted/dev environment)
                String encoded = passwordEncoder.encode(stored);
                u.setPassword(encoded);
                userRepository.save(u);
                System.out.println("Encoded plaintext password for user=" + u.getEmail());
            }
        }
    }
}
