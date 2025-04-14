package org.example.liquoriceauthenticationserver.config.security;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import org.example.liquoriceauthenticationserver.models.User;
import org.example.liquoriceauthenticationserver.repsitories.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class GoogleTokenAuthenticationProviderTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private GoogleIdTokenVerifier verifier;

    @Mock
    private GoogleIdToken googleIdToken;

    @Mock
    private Payload payload;

    @InjectMocks
    private GoogleTokenAuthenticationProvider authProvider;

    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_NAME = "Test User";
    private static final String TEST_TOKEN = "valid-token";

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authProvider, "clientId", "test-client-id");
        ReflectionTestUtils.setField(authProvider, "verifier", verifier);
    }

    @Test
    void authenticate_ShouldThrowException_WhenTokenIsInvalid() throws Exception {
        when(verifier.verify("invalid-token")).thenReturn(null);
        
        assertThrows(AuthenticationException.class, () -> 
            authProvider.authenticate("invalid-token"));
    }

    @Test
    void authenticate_ShouldCreateNewUser_WhenEmailNotFound() throws Exception {
        when(verifier.verify(TEST_TOKEN)).thenReturn(googleIdToken);
        when(googleIdToken.getPayload()).thenReturn(payload);
        when(payload.getEmail()).thenReturn(TEST_EMAIL);
        when(payload.get("name")).thenReturn(TEST_NAME);
        
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        Authentication result = authProvider.authenticate(TEST_TOKEN);

        verify(userRepository).findByEmail(TEST_EMAIL);
        verify(userRepository).save(any(User.class));
        
        assertNotNull(result);
        User user = (User) result.getPrincipal();
        assertEquals(TEST_EMAIL, user.getEmail());
        assertEquals(TEST_NAME, user.getName());
        assertEquals(User.Role.CUSTOMER, user.getRole());
        assertTrue(user.isGoogleAuthenticated());
    }

    @Test
    void authenticate_ShouldUpdateExistingUser_WhenEmailFound() throws Exception {
        when(verifier.verify(TEST_TOKEN)).thenReturn(googleIdToken);
        when(googleIdToken.getPayload()).thenReturn(payload);
        when(payload.getEmail()).thenReturn(TEST_EMAIL);
        when(payload.get("name")).thenReturn(TEST_NAME);
        
        User existingUser = User.builder()
                .email(TEST_EMAIL)
                .name(TEST_NAME)
                .role(User.Role.CUSTOMER)
                .googleAuthenticated(false)
                .build();
        
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(existingUser));
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        Authentication result = authProvider.authenticate(TEST_TOKEN);

        verify(userRepository).findByEmail(TEST_EMAIL);
        verify(userRepository).save(any(User.class));
        
        assertNotNull(result);
        User user = (User) result.getPrincipal();
        assertEquals(TEST_EMAIL, user.getEmail());
        assertTrue(user.isGoogleAuthenticated());
    }
}