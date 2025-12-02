package tech.buildrun.springsecurity.controller;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

//✅ DEPOIS (Correto)
import org.springframework.security.oauth2.jwt.JwtClaimsSet;

import tech.buildrun.springsecurity.controller.dto.LoginRequest;
import tech.buildrun.springsecurity.controller.dto.LoginResponse;
import tech.buildrun.springsecurity.entities.Role;
import tech.buildrun.springsecurity.repository.UserRepository;


@RestController
public class TokenController {
    
    // ✅ CONSTANTES ADICIONADAS
    private static final String ISSUER = "mybackend";
    private static final long TOKEN_EXPIRATION_SECONDS = 300L;
    private static final String INVALID_CREDENTIALS_MESSAGE = "user or password is invalid";
    private static final String LOGIN_ENDPOINT = "/login";
    
    private final JwtEncoder jwtEncoder;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    
    public TokenController(JwtEncoder jwtEncoder, 
                          UserRepository userRepository,
                          BCryptPasswordEncoder passwordEncoder) {
        this.jwtEncoder = jwtEncoder;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    
    @PostMapping(LOGIN_ENDPOINT) // ✅ Usando constante
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        
        var user = userRepository.findByUsername(loginRequest.username());
        
        // ✅ Usando constante na mensagem de erro
        if(user.isEmpty() || !user.get().isLoginCorrect(loginRequest, passwordEncoder)) {
            throw new BadCredentialsException(INVALID_CREDENTIALS_MESSAGE);
        }
        
        var now = Instant.now();
        
        var scopes = user.get().getRoles()
        		.stream()
        		.map(Role::getName) // ← Adiciona prefixo
        		.collect(Collectors.joining(""));
        
        
        var claims = JwtClaimsSet.builder()
                .issuer(ISSUER) // ✅  Quem emitiu o token
                .subject(user.get().getUserId().toString()) // id do usuario
                .issuedAt(now)  // Data de criação
                .expiresAt(now.plusSeconds(TOKEN_EXPIRATION_SECONDS)) // Expiracao
                .claim("scope", scopes)
                .build();
        
        var jwtValue = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        
        // ✅ Usando constante no tempo de expiração
        return ResponseEntity.ok(new LoginResponse(jwtValue, TOKEN_EXPIRATION_SECONDS));
    }
}