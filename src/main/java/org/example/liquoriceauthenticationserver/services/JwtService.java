package org.example.liquoriceauthenticationserver.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.example.liquoriceauthenticationserver.config.Constants;
import org.example.liquoriceauthenticationserver.config.JwtConfig;
import org.example.liquoriceauthenticationserver.models.User;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtService {
    private final JwtConfig jwtConfig;

    public String generateAccessToken(Authentication authentication) {
        return generateToken(authentication, jwtConfig.getAccessTokenExpiration());
    }

    public String generateAccessToken(String refreshToken) {
        try {
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(refreshToken)
                .getBody();

            return Jwts.builder()
                    .setSubject(claims.getSubject())
                    .claim("role", claims.get("role", String.class))
                    .setId(UUID.randomUUID().toString())
                    .setIssuedAt(Date.from(Instant.now()))
                    .setExpiration(Date.from(Instant.now().plus(jwtConfig.getAccessTokenExpiration(), ChronoUnit.MILLIS)))
                    .signWith(getSigningKey(), Constants.JWT_SIGNATURE_ALGORITHM)
                    .compact();
        } catch (Exception e) {
            return null;
        }
    }

    public String generateRefreshToken(Authentication authentication) {
        return generateToken(authentication, jwtConfig.getRefreshTokenExpiration());
    }

    private String generateToken(Authentication authentication, long expiration) {
        User user = (User) authentication.getPrincipal();
        Instant now = Instant.now();

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim("role", user.getRole())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plus(expiration, ChronoUnit.MILLIS)))
                .signWith(getSigningKey(), Constants.JWT_SIGNATURE_ALGORITHM)
                .compact();
    }

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(jwtConfig.getSecretKey().getBytes());
    }

    public long getTokenRemainingLifetimeMillis(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

            Date expiration = claims.getExpiration();

            long remainingTime = expiration.getTime() - System.currentTimeMillis();

            return Math.max(0, remainingTime);
        } catch (Exception e) {
            return 0;
        }
    }
}
