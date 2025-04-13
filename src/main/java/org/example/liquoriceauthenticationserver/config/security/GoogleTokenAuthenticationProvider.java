package org.example.liquoriceauthenticationserver.config.security;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import lombok.RequiredArgsConstructor;
import org.example.liquoriceauthenticationserver.models.User;
import org.example.liquoriceauthenticationserver.repsitories.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collections;

@Component
@RequiredArgsConstructor
public class GoogleTokenAuthenticationProvider {

    private final UserRepository userRepository;
    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    public Authentication authenticate(String idTokenString) throws AuthenticationException {
        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
                    new NetHttpTransport(), new GsonFactory())
                    .setAudience(Collections.singletonList(clientId))
                    .build();

            GoogleIdToken idToken = verifier.verify(idTokenString);
            if (idToken == null) {
                throw new AuthenticationException("Invalid ID token") {};
            }

            Payload payload = idToken.getPayload();
            String email = payload.getEmail();
            String name = (String) payload.get("name");

            User user = userRepository.findByEmail(email)
                    .orElseGet(() -> {
                        User newUser = User.builder()
                                .email(email)
                                .name(name)
                                .role(User.Role.CUSTOMER)
                                .googleAuthenticated(true)
                                .build();
                        return userRepository.save(newUser);
                    });

            if (!user.isGoogleAuthenticated()) {
                user.setGoogleAuthenticated(true);
                userRepository.save(user);
            }
            return new UsernamePasswordAuthenticationToken(
                user,
                null,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
            );
        } catch (Exception e) {
            throw new AuthenticationException("Failed to authenticate Google token: " + e.getMessage()) {};
        }
    }
}