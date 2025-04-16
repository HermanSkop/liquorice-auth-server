package org.example.liquoriceauthenticationserver.services;

import org.example.liquoriceauthenticationserver.models.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.util.List;

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
class JwtServiceTest {

    @InjectMocks
    private JwtService jwtService;

    private Authentication authentication;

    @BeforeEach
    void setUp() {
        User testUser = User.builder()
                .id("123")
                .email("test@example.com")
                .role(User.Role.CUSTOMER)
                .build();

        authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(testUser);

        ReflectionTestUtils.setField(jwtService, "secretKey", "yourTestSecretKeyHereItShouldBeAtLeast256BitsLong");
        ReflectionTestUtils.setField(jwtService, "accessTokenExpiration", 300000L);
        ReflectionTestUtils.setField(jwtService, "refreshTokenExpiration", 3000000L);
    }

    @Test
    void generateAccessToken_ShouldCreateValidToken() {
        String token = jwtService.generateAccessToken(authentication);
        
        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void generateRefreshToken_ShouldCreateValidToken() {
        String token = jwtService.generateRefreshToken(authentication);
        
        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void generateAccessTokenFromRefreshToken_ShouldCreateNewAccessToken() {
        String refreshToken = jwtService.generateRefreshToken(authentication);
        String accessToken = jwtService.generateAccessTokenFromRefreshToken(refreshToken);
        
        assertNotNull(accessToken);
        assertFalse(accessToken.isEmpty());
        
        Claims claims = extractAllClaims(accessToken);
        assertEquals("ACCESS", claims.get("type"));
        
        @SuppressWarnings("unchecked")
        List<String> roles = claims.get("roles", List.class);
        assertNotNull(roles);
        assertFalse(roles.isEmpty());
        assertEquals("CUSTOMER", roles.get(0));
    }

    @Test
    void generateAccessTokenFromRefreshToken_ShouldThrowException_WhenUsingAccessToken() {
        String accessToken = jwtService.generateAccessToken(authentication);
        
        assertThrows(IllegalArgumentException.class, 
            () -> jwtService.generateAccessTokenFromRefreshToken(accessToken));
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor("yourTestSecretKeyHereItShouldBeAtLeast256BitsLong".getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
