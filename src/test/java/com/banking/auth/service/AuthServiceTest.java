package com.banking.auth.service;

import com.banking.auth.dto.LoginRequest;
import com.banking.auth.dto.RegisterRequest;
import com.banking.auth.entity.User;
import com.banking.auth.repository.UserRepository;
import com.banking.common.exception.ResourceNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthService authService;

    @Test
    void registerCreatesUserWithEncodedPassword() {
        UUID userId = UUID.randomUUID();
        RegisterRequest request = new RegisterRequest("user@example.com", "plain-password", "Test User");

        when(userRepository.existsByEmail(request.email())).thenReturn(false);
        when(passwordEncoder.encode(request.password())).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(userId);
            return user;
        });

        var response = authService.register(request);

        assertThat(response.userId()).isEqualTo(userId.toString());
        assertThat(response.email()).isEqualTo(request.email());
        verify(userRepository).save(org.mockito.ArgumentMatchers.argThat(user ->
                user.getEmail().equals(request.email())
                        && user.getPasswordHash().equals("encoded-password")
                        && user.getFullName().equals(request.fullName())));
    }

    @Test
    void registerRejectsExistingEmail() {
        RegisterRequest request = new RegisterRequest("user@example.com", "plain-password", "Test User");
        when(userRepository.existsByEmail(request.email())).thenReturn(true);

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Email already registered");

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void loginReturnsTokenForValidCredentials() {
        UUID userId = UUID.randomUUID();
        User user = new User();
        user.setId(userId);
        user.setEmail("user@example.com");
        user.setPasswordHash("encoded-password");

        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("plain-password", user.getPasswordHash())).thenReturn(true);
        when(jwtService.generateToken(userId.toString())).thenReturn("access-token");
        when(jwtService.getExpirationMs()).thenReturn(3_600_000L);

        var response = authService.login(new LoginRequest(user.getEmail(), "plain-password"));

        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.expiresIn()).isEqualTo(3600);
        assertThat(response.userId()).isEqualTo(userId.toString());
    }

    @Test
    void loginRejectsInvalidPassword() {
        User user = new User();
        user.setEmail("user@example.com");
        user.setPasswordHash("encoded-password");

        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", user.getPasswordHash())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(new LoginRequest(user.getEmail(), "wrong-password")))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessage("Invalid credentials");

        verify(jwtService, never()).generateToken(any());
    }
}
