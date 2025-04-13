package org.example.liquoriceauthenticationserver.config.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@Getter
@Setter
@ConfigurationProperties(prefix = "jwt")
public class JwtConfig {
    private String secretKey;
    private long accessTokenExpiration;
    private long refreshTokenExpiration;
}
