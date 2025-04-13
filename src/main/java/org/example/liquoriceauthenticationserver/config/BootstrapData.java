package org.example.liquoriceauthenticationserver.config;

import lombok.extern.slf4j.Slf4j;
import org.example.liquoriceauthenticationserver.models.User;
import org.example.liquoriceauthenticationserver.repsitories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
@Configuration
public class BootstrapData {
    @Bean
    CommandLineRunner initDatabase(UserRepository userRepository, PasswordEncoder passwordEncoder, MongoTemplate mongoTemplate) {
        return args -> {
            mongoTemplate.getDb().drop();

                User admin = User.builder().email("Admin1@a.a").role(User.Role.ADMIN).password(passwordEncoder.encode("Admin1@a.a")).build();
            userRepository.save(admin);
        };
    }
}