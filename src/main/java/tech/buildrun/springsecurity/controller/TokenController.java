package tech.buildrun.springsecurity.controller;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.security.oauth2.jwt.JwtClaimsSet;

import tech.buildrun.springsecurity.controller.dto.LoginRequest;
import tech.buildrun.springsecurity.controller.dto.LoginResponse;
import tech.buildrun.springsecurity.controller.dto.RefreshRequest;
import tech.buildrun.springsecurity.entities.RefreshToken;
import tech.buildrun.springsecurity.entities.Role;
import tech.buildrun.springsecurity.repository.RefreshTokenRepository;
import tech.buildrun.springsecurity.repository.UserRepository;

@RestController
public class TokenController {

    private static final String ISSUER = "mybackend";
    private static final long ACCESS_TOKEN_EXPIRATION = 300L;   // 5 min
    private static final long REFRESH_TOKEN_EXPIRATION_DAYS = 30;

    private static final String INVALID_CREDENTIALS = "user or password is invalid";

    private final JwtEncoder jwtEncoder;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public TokenController(JwtEncoder jwtEncoder,
                           UserRepository userRepository,
                           RefreshTokenRepository refreshTokenRepository,
                           BCryptPasswordEncoder passwordEncoder) {

        this.jwtEncoder = jwtEncoder;
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {

        var user = userRepository.findByUsername(loginRequest.username());

        if (user.isEmpty() || !user.get().isLoginCorrect(loginRequest, passwordEncoder)) {
            throw new BadCredentialsException(INVALID_CREDENTIALS);
        }

        var now = Instant.now();

        var scopes = user.get().getRoles()
                .stream()
                .map(Role::getName)
                .collect(Collectors.joining(""));

        // --- Cria JWT ---
        var claims = JwtClaimsSet.builder()
                .issuer(ISSUER)
                .subject(user.get().getUserId().toString())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(ACCESS_TOKEN_EXPIRATION))
                .claim("scope", scopes)
                .build();

        String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        // ---- Cria Refresh Token ---
        String refreshTokenValue = UUID.randomUUID().toString();

        var refreshToken = new RefreshToken();
        refreshToken.setToken(refreshTokenValue);
        refreshToken.setUserId(user.get().getUserId());
        refreshToken.setExpiration(now.plus(REFRESH_TOKEN_EXPIRATION_DAYS, ChronoUnit.DAYS));

        refreshTokenRepository.save(refreshToken);

        return ResponseEntity.ok(
                new LoginResponse(accessToken, refreshTokenValue, ACCESS_TOKEN_EXPIRATION)
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@RequestBody RefreshRequest request) {

        var stored = refreshTokenRepository.findByToken(request.refreshToken())
                .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));

        if (stored.getExpiration().isBefore(Instant.now())) {
            throw new BadCredentialsException("Refresh token expired");
        }

        var user = userRepository.findById(stored.getUserId()).get();

        var now = Instant.now();

        var scopes = user.getRoles()
                .stream()
                .map(Role::getName)
                .collect(Collectors.joining(""));

        // --- Novo Access Token ---
        var claims = JwtClaimsSet.builder()
                .issuer(ISSUER)
                .subject(user.getUserId().toString())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(ACCESS_TOKEN_EXPIRATION))
                .claim("scope", scopes)
                .build();

        String newAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        return ResponseEntity.ok(
                new LoginResponse(newAccessToken, request.refreshToken(), ACCESS_TOKEN_EXPIRATION)
        );
    }
}
