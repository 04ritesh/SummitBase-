package com.trek.summitBase.controller;

import com.trek.summitBase.dto.AuthResponse;
import com.trek.summitBase.dto.LoginRequest;
import com.trek.summitBase.dto.RegisterRequest;
import com.trek.summitBase.entity.User;
import com.trek.summitBase.enums.AuthProvider;
import com.trek.summitBase.service.JwtService;
import com.trek.summitBase.service.TokenStore;
import com.trek.summitBase.service.UserService;
import io.jsonwebtoken.Claims;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;
    private final TokenStore tokenStore;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        User user = userService.registerLocalUser(
                request.getEmail(), request.getPassword(), request.getName());

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        tokenStore.saveRefreshToken(user.getId(), refreshToken);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new AuthResponse(accessToken, refreshToken, user.getEmail(), user.getName()));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        User user = userService.findByEmail(request.getEmail());

        if (user.getProvider() != AuthProvider.LOCAL) {
            throw new RuntimeException("Please login with " + user.getProvider());
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        tokenStore.saveRefreshToken(user.getId(), refreshToken);

        return ResponseEntity.ok(
                new AuthResponse(accessToken, refreshToken, user.getEmail(), user.getName()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> body) {
        Claims claims = jwtService.validateToken(body.get("refreshToken"));
        User user = userService.findById(claims.getSubject());
        String newAccessToken = jwtService.generateAccessToken(user);
        return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String header) {
        String token = header.substring(7);
        Claims claims = jwtService.validateToken(token);
        long ttl = claims.getExpiration().getTime() - System.currentTimeMillis();
        tokenStore.blacklistToken(claims.getId(), Duration.ofMillis(ttl));
        return ResponseEntity.ok(Map.of("message", "logged out"));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(@RequestHeader("Authorization") String header) {
        String token = header.substring(7);
        Claims claims = jwtService.validateToken(token);
        User user = userService.findById(claims.getSubject());
        return ResponseEntity.ok(
                new AuthResponse(null, null, user.getEmail(), user.getName()));
    }
}
