package tech.buildrun.springsecurity.services;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import tech.buildrun.springsecurity.controller.dto.*;
import tech.buildrun.springsecurity.entities.RefreshToken;
import tech.buildrun.springsecurity.repository.RefreshTokenRepository;
import tech.buildrun.springsecurity.repository.UserRepository;

@Service
public class TokenService {

    private static final String ISSUER = "mybackend";
    private static final long ACCESS_TOKEN_EXPIRATION = 300L;
    private static final long REFRESH_TOKEN_EXPIRATION_DAYS = 30;
    private static final String INVALID_CREDENTIALS = "user or password is invalid";

    private final JwtEncoder jwtEncoder;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    
    public enum RefreshStatus {
        VALIDO, EXPIRADO, INVALIDO
    }


    public TokenService(JwtEncoder jwtEncoder,
                        UserRepository userRepository,
                        RefreshTokenRepository refreshTokenRepository,
                        BCryptPasswordEncoder passwordEncoder) {
        this.jwtEncoder = jwtEncoder;
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // 🔐 Login
    public LoginResponse login(LoginRequest request) {
        var user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new BadCredentialsException(INVALID_CREDENTIALS));

        if (!user.isLoginCorrect(request, passwordEncoder)) {
            throw new BadCredentialsException(INVALID_CREDENTIALS);
        }

        var now = Instant.now();
        var scopes = user.getRoles()
                .stream()
                .map(role -> "SCOPE_" + role.getName())
                .collect(Collectors.joining(" "));

        String accessToken = generateAccessToken(user.getUserId(), scopes);

        String refreshTokenValue = UUID.randomUUID().toString();

        var refreshToken = new RefreshToken();
        refreshToken.setToken(refreshTokenValue);
        refreshToken.setUserId(user.getUserId());
        refreshToken.setExpiration(now.plus(REFRESH_TOKEN_EXPIRATION_DAYS, ChronoUnit.DAYS));

        refreshTokenRepository.save(refreshToken);

        return new LoginResponse(accessToken, refreshTokenValue, ACCESS_TOKEN_EXPIRATION);
    }

    // 🔁 Refresh
    public LoginResponse refresh(RefreshRequest request) {
        var stored = refreshTokenRepository.findByToken(request.refreshToken())
                .orElseThrow(() -> new BadCredentialsException("Refresh token inválido"));

        if (stored.getExpiration().isBefore(Instant.now())) {
            throw new RuntimeException("Refresh token expirado");
        }

        var user = userRepository.findById(stored.getUserId())
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        var scopes = user.getRoles()
                .stream()
                .map(role -> "SCOPE_" + role.getName())
                .collect(Collectors.joining(" "));

        String newAccessToken = generateAccessToken(user.getUserId(), scopes);

        return new LoginResponse(newAccessToken, request.refreshToken(), ACCESS_TOKEN_EXPIRATION);
    }

    // 🚪 Logout
    public void logout(RefreshRequest request) {
        var token = refreshTokenRepository.findByToken(request.refreshToken())
                .orElseThrow(() -> new RuntimeException("Token não encontrado"));

        refreshTokenRepository.delete(token);
    }

    // ✅ Status
    public RefreshStatusResponse refreshStatus(RefreshRequest request) {

        var storedOptional = refreshTokenRepository.findByToken(request.refreshToken());

        if (storedOptional.isEmpty()) {
            return new RefreshStatusResponse(RefreshStatus.INVALIDO, "Refresh token inválido.");
        }

        var stored = storedOptional.get();

        if (stored.getExpiration().isBefore(Instant.now())) {
            return new RefreshStatusResponse(RefreshStatus.EXPIRADO, "Refresh token expirado.");
        }

        //return new RefreshStatusResponse("VALIDO", "Refresh token válido.");
        return new RefreshStatusResponse(RefreshStatus.VALIDO, "Refresh token válido.");
    }

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
}
