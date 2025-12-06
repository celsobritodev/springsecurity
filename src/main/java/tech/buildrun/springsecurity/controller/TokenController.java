package tech.buildrun.springsecurity.controller;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import tech.buildrun.springsecurity.controller.dto.LoginRequest;
import tech.buildrun.springsecurity.controller.dto.LoginResponse;
import tech.buildrun.springsecurity.controller.dto.RefreshRequest;
import tech.buildrun.springsecurity.controller.dto.RefreshStatusResponse;
import tech.buildrun.springsecurity.entities.RefreshToken;
import tech.buildrun.springsecurity.repository.RefreshTokenRepository;
import tech.buildrun.springsecurity.repository.UserRepository;

@RestController
public class TokenController {

    // 🔥 CONSTANTES DO CONTROLLER
    private static final String LOGIN_ENDPOINT = "/login";
    private static final String REFRESH_ENDPOINT = "/refresh";
    private static final String LOGOUT_ENDPOINT = "/logout";
    private static final String TEST_AUTH_ENDPOINT = "/test-auth";
    private static final String REFRESH_STATUS_ENDPOINT = "/refreshstatus";


    private static final String ISSUER = "mybackend";

    private static final long ACCESS_TOKEN_EXPIRATION = 300L; // 5 minutos
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
    // ✅ MÉTODO AUXILIAR PARA GERAR ACCESS TOKEN
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

    // -----------------------------------------
    // ✅ LOGIN
    // -----------------------------------------
    @PostMapping(LOGIN_ENDPOINT)
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

        String accessToken = generateAccessToken(userEntity.getUserId(), scopes);

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
    
    

    // -----------------------------------------
    // ✅ REFRESH TOKEN
    // -----------------------------------------
    @PostMapping(REFRESH_ENDPOINT)
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest request) {

        var storedOptional = refreshTokenRepository.findByToken(request.refreshToken());

        // ✅ CASO 1 — TOKEN NÃO EXISTE → FOI REVOGADO
        if (storedOptional.isEmpty()) {
            System.out.println("❌ Tentativa de uso de refresh token revogado ou inexistente.");

            return ResponseEntity
                    .status(401)
                    .body("{\"erro\": \"Refresh token inválido: token foi revogado, não existe ou formato invalido\"}");
        }

        var stored = storedOptional.get();

        // ✅ CASO 2 — TOKEN EXISTE, MAS ESTÁ EXPIRADO
        if (stored.getExpiration().isBefore(Instant.now())) {
            System.out.println("⚠️ Tentativa de uso de refresh token expirado.");

            return ResponseEntity
                    .status(401)
                    .body("{\"erro\": \"Refresh token expirado. Faça login novamente.\"}");
        }

        // ✅ CASO 3 — TOKEN VÁLIDO → GERA NOVO ACCESS TOKEN
        var user = userRepository.findById(stored.getUserId());

        if (user.isEmpty()) {
            return ResponseEntity
                    .status(404)
                    .body("{\"erro\": \"Usuário não encontrado.\"}");
        }

        var scopes = user.get().getRoles()
                .stream()
                .map(role -> "SCOPE_" + role.getName())
                .collect(Collectors.joining(" "));

        String newAccessToken = generateAccessToken(user.get().getUserId(), scopes);

        System.out.println("✅ Refresh token válido. Novo access token gerado.");

        return ResponseEntity.ok(
                new LoginResponse(newAccessToken, request.refreshToken(), ACCESS_TOKEN_EXPIRATION)
        );
    }


  
    
    

    // -----------------------------------------
    // ✅ LOGOUT
    // -----------------------------------------
    @PostMapping(LOGOUT_ENDPOINT)
    @Transactional
    public ResponseEntity<String> logout(@RequestBody RefreshRequest request) {

    	var refreshTokenOptional = refreshTokenRepository.findByToken(request.refreshToken());

        if (refreshTokenOptional.isEmpty()) {
            System.out.println("⚠️ Tentativa de logout com refresh token inexistente.");

            return ResponseEntity
                    .status(404)
                    .body("Refresh token não encontrado ou já foi revogado.");
        }

        refreshTokenRepository.delete(refreshTokenOptional.get());

        System.out.println("✅ Logout realizado com sucesso. Refresh token removido.");

        return ResponseEntity.ok("Logout realizado com sucesso.");
    }
    
    
    
    
    

    // -----------------------------------------
    // ✅ TESTE DE AUTENTICAÇÃO
    // -----------------------------------------
    @GetMapping(TEST_AUTH_ENDPOINT)
    public String testAuth(JwtAuthenticationToken token) {

        if (token == null) {
            return "Token is NULL!";
        }

        return "Authenticated! User: " + token.getName() +
               " | Authorities: " + token.getAuthorities();
    }
    
    
    
    @PostMapping(REFRESH_STATUS_ENDPOINT)
    public ResponseEntity<RefreshStatusResponse> refreshStatus(@RequestBody RefreshRequest request) {

        var storedOptional = refreshTokenRepository.findByToken(request.refreshToken());

        // ✅ CASO 1 — INVÁLIDO (NUNCA EXISTIU OU FOI REVOGADO)
        if (storedOptional.isEmpty()) {
            System.out.println("❌ Token inválido: inexistente ou revogado.");

            return ResponseEntity.status(401).body(
                new RefreshStatusResponse(
                    "INVALIDO",
                    "Refresh token inválido."
                )
            );
        }

        var stored = storedOptional.get();

        // ✅ CASO 2 — EXPIRADO
        if (stored.getExpiration().isBefore(Instant.now())) {
            System.out.println("⚠️ Token inválido: expirado.");

            return ResponseEntity.status(401).body(
                new RefreshStatusResponse(
                    "EXPIRADO",
                    "Refresh token expirado."
                )
            );
        }

        // ✅ CASO 3 — VÁLIDO
        System.out.println("✅ Refresh token válido.");

        return ResponseEntity.ok(
            new RefreshStatusResponse(
                "VALIDO",
                "Refresh token está válido."
            )
        );
    }

}
