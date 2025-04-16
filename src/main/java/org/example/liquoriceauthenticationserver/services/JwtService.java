package org.example.liquoriceauthenticationserver.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.example.liquoriceauthenticationserver.models.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${jwt.secret-key}")
    private String secretKey;

    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    private User getUserFromAuthentication(Authentication authentication) {
        if (authentication.getPrincipal() instanceof User) {
            return (User) authentication.getPrincipal();
        }
        throw new IllegalArgumentException("Invalid authentication principal");
    }

    public String generateAccessToken(Authentication authentication) {
        User user = getUserFromAuthentication(authentication);
        return generateToken(user.getId(), user.getEmail(), user.getRole().name(), "ACCESS", accessTokenExpiration);
    }

    public String generateRefreshToken(Authentication authentication) {
        User user = getUserFromAuthentication(authentication);
        return generateToken(user.getId(), user.getEmail(), user.getRole().name(), "REFRESH", refreshTokenExpiration);
    }

    public String generateAccessTokenFromRefreshToken(String refreshToken) {
        Claims claims = extractAllClaims(refreshToken);
        
        if (!"REFRESH".equals(claims.get("type", String.class))) {
            throw new IllegalArgumentException("Invalid token type");
        }

        String role = claims.get("roles", List.class).get(0).toString();
        
        return generateToken(
                claims.get("userId", String.class),
                claims.get("email", String.class),
                role,
                "ACCESS",
                accessTokenExpiration
        );
    }

    public long getTokenRemainingLifetimeMillis(String token) {
        return extractAllClaims(token).getExpiration().getTime() - System.currentTimeMillis();
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private String generateToken(String userId, String email, String role, String tokenType, long expiration) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", email);
        claims.put("type", tokenType);
        claims.put("roles", List.of(role));
        claims.put("userId", userId);
        
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()), SignatureAlgorithm.HS256)
                .compact();
    }
}