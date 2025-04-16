package org.example.liquoriceauthenticationserver.controllers;

import org.example.liquoriceauthenticationserver.dtos.AuthRequestDto;
import org.example.liquoriceauthenticationserver.dtos.AuthResponseDto;
import org.example.liquoriceauthenticationserver.models.User;
import org.example.liquoriceauthenticationserver.services.JwtService;
import org.example.liquoriceauthenticationserver.services.TokenBlacklistService;
import org.example.liquoriceauthenticationserver.services.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ActiveProfiles;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
class AuthControllerTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtService jwtService;

    @Mock
    private UserService userService;

    @InjectMocks
    private AuthController authController;

    private AuthRequestDto authRequest;
    private Authentication authentication;
    private User testUser;

    @BeforeEach
    void setUp() {
        authRequest = new AuthRequestDto("test@example.com", "password123");
        testUser = User.builder()
                .id("123")
                .email("test@example.com")
                .role(User.Role.CUSTOMER)
                .build();
        authentication = new UsernamePasswordAuthenticationToken(testUser, null);
    }

    @Test
    void login_ShouldReturnTokens_WhenCredentialsAreValid() {
        when(authenticationManager.authenticate(any())).thenReturn(authentication);
        when(jwtService.generateAccessToken(authentication)).thenReturn("access-token");
        when(jwtService.generateRefreshToken(authentication)).thenReturn("refresh-token");

        ResponseEntity<AuthResponseDto> response = authController.login(authRequest);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("access-token", response.getBody().getAccessToken());
        assertEquals("refresh-token", response.getBody().getRefreshToken());
    }

    @Test
    void login_ShouldHandleErrorResponse_WhenCredentialsAreInvalid() {
        when(authenticationManager.authenticate(any()))
            .thenThrow(new BadCredentialsException("Invalid email or password"));

        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> authController.login(authRequest)
        );

        ResponseEntity<Object> response = new GlobalExceptionHandler()
            .handleIllegalArgumentException(exception);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        assertNotNull(body);
        assertEquals("Invalid arguments passed: email or password", body.get("message"));
        assertEquals("IllegalArgumentException", body.get("error"));
    }

    @Test
    void register_ShouldReturnCreated_WhenRegistrationSucceeds() {
        when(userService.registerCustomer(authRequest.getEmail(), authRequest.getPassword()))
                .thenReturn(Optional.of(testUser));

        ResponseEntity<Void> response = authController.register(authRequest);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
    }

    @Test
    void register_ShouldThrowException_WhenUserExists() {
        when(userService.registerCustomer(authRequest.getEmail(), authRequest.getPassword()))
                .thenReturn(Optional.empty());

        assertThrows(IllegalArgumentException.class, () -> authController.register(authRequest));
    }
}