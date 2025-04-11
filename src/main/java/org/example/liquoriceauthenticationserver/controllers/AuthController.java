package org.example.liquoriceauthenticationserver.controllers;

import jakarta.validation.Valid;
import lombok.Getter;
import org.example.liquoriceauthenticationserver.config.Constants;
import org.example.liquoriceauthenticationserver.dtos.AuthRequestDto;
import org.example.liquoriceauthenticationserver.dtos.AuthResponseDto;
import org.example.liquoriceauthenticationserver.dtos.RefreshTokenRequestDto;
import org.example.liquoriceauthenticationserver.services.JwtService;
import org.example.liquoriceauthenticationserver.services.TokenBlacklistService;
import org.example.liquoriceauthenticationserver.services.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping(Constants.BASE_PATH)
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserService userService;
    private final TokenBlacklistService tokenBlacklistService;

    public AuthController(AuthenticationManager authenticationManager, JwtService jwtService, UserService userService, TokenBlacklistService tokenBlacklistService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.userService = userService;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    @GetMapping("/login")
    public ResponseEntity<AuthResponseDto> login(@RequestBody @Valid AuthRequestDto request) {
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

            String accessToken = jwtService.generateAccessToken(authentication);
            String refreshToken = jwtService.generateRefreshToken(authentication);

            return ResponseEntity.ok(new AuthResponseDto(accessToken, refreshToken));
        } catch (Exception e) {
            throw new IllegalArgumentException("email or password", e);
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDto> refresh(@RequestBody RefreshTokenRequestDto request) {
        if (jwtService.getTokenRemainingLifetimeMillis(request.getRefreshToken()) <= 0) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        String accessToken = jwtService.generateAccessToken(request.getRefreshToken());
        return ResponseEntity.ok(new AuthResponseDto(accessToken, request.getRefreshToken()));
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestBody @Valid AuthRequestDto request) {
        return userService.registerCustomer(request.getEmail(), request.getPassword())
                .map(user -> ResponseEntity.status(HttpStatus.CREATED).<Void>build())
                .orElseThrow(() -> new IllegalArgumentException("User already exists with this email"));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody Map<String, String> tokens) {
        String accessToken = tokens.get("accessToken");
        String refreshToken = tokens.get("refreshToken");

        if (accessToken != null && !accessToken.isEmpty()) {
            tokenBlacklistService.blacklistToken(accessToken, "Logout");
        }

        if (refreshToken != null && !refreshToken.isEmpty()) {
            tokenBlacklistService.blacklistToken(refreshToken, "Logout");
        }

        return ResponseEntity.ok().build();
    }
}

