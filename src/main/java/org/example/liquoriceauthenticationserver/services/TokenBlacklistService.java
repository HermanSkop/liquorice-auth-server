package org.example.liquoriceauthenticationserver.services;

import lombok.RequiredArgsConstructor;
import org.example.liquoriceauthenticationserver.config.Constants;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final RedisTemplate<String, String> redisTemplate;
    private final JwtService jwtService;

    public void blacklistToken(String token, String reason) {
        long expirationWithSkew = jwtService.getTokenRemainingLifetimeMillis(token) +
                                Constants.JWT_ACCESS_TOKEN_SECONDS_TIMEOUT_SKEW * 1000;

        redisTemplate.opsForValue().set(token, reason, expirationWithSkew, TimeUnit.MILLISECONDS);
    }

}