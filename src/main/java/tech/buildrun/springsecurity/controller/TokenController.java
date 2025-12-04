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
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;

import tech.buildrun.springsecurity.controller.dto.LoginRequest;
import tech.buildrun.springsecurity.controller.dto.LoginResponse;
import tech.buildrun.springsecurity.controller.dto.RefreshRequest;
import tech.buildrun.springsecurity.entities.RefreshToken;
import tech.buildrun.springsecurity.repository.RefreshTokenRepository;
import tech.buildrun.springsecurity.repository.UserRepository;

@RestController
public class TokenController {

    private static final String ISSUER = "mybackend";
    private static final long ACCESS_TOKEN_EXPIRATION = 600L;   // 10 min
    private static final long REFRESH_TOKEN_EXPIRATION_DAYS = 30;

    private static final String INVALID_CREDENTIALS = "user or password is invalid";

    private final JwtEncoder jwtEncoder;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public TokenController(
            JwtEncoder jwtEncoder,
            UserRepository userRepository,
            RefreshTokenRepository refreshTokenRepository,
            BCryptPasswordEncoder passwordEncoder) {

        this.jwtEncoder = jwtEncoder;
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // -----------------------------------------
    // MÉTODO AUXILIAR PARA GERAR ACCESS TOKEN
    // -----------------------------------------
    private String generateAccessToken(UUID userId, String scopes) {

        var now = Instant.now();

        var claims = JwtClaimsSet.builder()
                .issuer(ISSUER)
                .subject(userId.toString())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(ACCESS_TOKEN_EXPIRATION))
                .claim("scope", scopes)
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {

        var user = userRepository.findByUsername(loginRequest.username());

        if (user.isEmpty() || !user.get().isLoginCorrect(loginRequest, passwordEncoder)) {
            throw new BadCredentialsException(INVALID_CREDENTIALS);
        }

        var userEntity = user.get();
        var now = Instant.now();

        var scopes = userEntity.getRoles()
                .stream()
                .map(role -> "SCOPE_" + role.getName())
                .collect(Collectors.joining(" "));

        // **Novo Access Token**
        String accessToken = generateAccessToken(userEntity.getUserId(), scopes);

        // **Refresh Token salvo no banco**
        String refreshTokenValue = UUID.randomUUID().toString();

        var refreshToken = new RefreshToken();
        refreshToken.setToken(refreshTokenValue);
        refreshToken.setUserId(userEntity.getUserId());
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

        var user = userRepository.findById(stored.getUserId())
                .orElseThrow(() -> new BadCredentialsException("User not found"));

        // --- Recria o scope (IMPORTANTE!) ---
        var scopes = user.getRoles()
                .stream()
                .map(role -> "SCOPE_" + role.getName())
                .collect(Collectors.joining(" "));

        // --- Gera novo access token válido ---
        String newAccessToken = generateAccessToken(user.getUserId(), scopes);

        return ResponseEntity.ok(
                new LoginResponse(newAccessToken, request.refreshToken(), ACCESS_TOKEN_EXPIRATION)
        );
    }
    
    
    @PostMapping("/logout")
    @Transactional
    public ResponseEntity<Void> logout(@RequestBody RefreshRequest request) {
        refreshTokenRepository.findByToken(request.refreshToken())
                .ifPresent(refreshTokenRepository::delete);
        return ResponseEntity.ok().build();
    }
    
    @GetMapping("/test-auth")
    public String testAuth(JwtAuthenticationToken token) {
        if (token == null) {
            return "Token is NULL!";
        }
        return "Authenticated! User: " + token.getName() + 
               " | Authorities: " + token.getAuthorities();
    }
    
    
}
