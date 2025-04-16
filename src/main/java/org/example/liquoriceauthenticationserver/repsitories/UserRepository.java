package org.example.liquoriceauthenticationserver.repsitories;

import jakarta.validation.constraints.Email;
import org.example.liquoriceauthenticationserver.models.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User, String> {
    Optional<User> findByEmail(@Email String email);

    boolean existsByEmail(String email);
}
