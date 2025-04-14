package org.example.liquoriceauthenticationserver.services;

import org.example.liquoriceauthenticationserver.models.User;
import org.example.liquoriceauthenticationserver.repsitories.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_PASSWORD = "password123";
    private static final String ENCODED_PASSWORD = "encodedPassword123";

    @BeforeEach
    void setUp() {
        lenient().when(passwordEncoder.encode(TEST_PASSWORD)).thenReturn(ENCODED_PASSWORD);
    }

    @Test
    void registerCustomer_ShouldCreateNewUser_WhenEmailNotExists() {
        when(passwordEncoder.encode(TEST_PASSWORD)).thenReturn(ENCODED_PASSWORD);
        when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId("123");
            return user;
        });

        Optional<User> result = userService.registerCustomer(TEST_EMAIL, TEST_PASSWORD);

        assertTrue(result.isPresent());
        assertEquals(TEST_EMAIL, result.get().getEmail());
        assertEquals(ENCODED_PASSWORD, result.get().getPassword());
        assertEquals(User.Role.CUSTOMER, result.get().getRole());
        verify(userRepository).save(any(User.class));
    }

    @Test
    void registerCustomer_ShouldReturnEmpty_WhenEmailExists() {
        when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(true);

        Optional<User> result = userService.registerCustomer(TEST_EMAIL, TEST_PASSWORD);

        assertTrue(result.isEmpty());
        verify(userRepository, never()).save(any(User.class));
    }
}