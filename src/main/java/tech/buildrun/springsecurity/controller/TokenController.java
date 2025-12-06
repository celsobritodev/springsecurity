package tech.buildrun.springsecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import tech.buildrun.springsecurity.controller.dto.LoginRequest;
import tech.buildrun.springsecurity.controller.dto.LoginResponse;
import tech.buildrun.springsecurity.controller.dto.RefreshRequest;
import tech.buildrun.springsecurity.controller.dto.RefreshStatusResponse;
import tech.buildrun.springsecurity.services.TokenService;

@RestController
public class TokenController {

    // ✅ CONSTANTES DOS ENDPOINTS
    private static final String LOGIN_ENDPOINT = "/login";
    private static final String REFRESH_ENDPOINT = "/refresh";
    private static final String LOGOUT_ENDPOINT = "/logout";
    private static final String REFRESH_STATUS_ENDPOINT = "/refreshstatus";
    private static final String TEST_AUTH_ENDPOINT = "/test-auth";

    // ✅ CONSTANTES DE MENSAGEM
    private static final String TOKEN_NULL_MESSAGE = "Token is NULL!";
    private static final String AUTH_SUCCESS_MESSAGE = "Authenticated! User: ";
    private static final String AUTHORITIES_MESSAGE = " | Authorities: ";

    private final TokenService tokenService;

    public TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping(LOGIN_ENDPOINT)
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(tokenService.login(request));
    }

    @PostMapping(REFRESH_ENDPOINT)
    public ResponseEntity<LoginResponse> refresh(@RequestBody RefreshRequest request) {
        return ResponseEntity.ok(tokenService.refresh(request));
    }

    @PostMapping(LOGOUT_ENDPOINT)
    public ResponseEntity<Void> logout(@RequestBody RefreshRequest request) {
        tokenService.logout(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping(REFRESH_STATUS_ENDPOINT)
    public ResponseEntity<RefreshStatusResponse> status(@RequestBody RefreshRequest request) {
        return ResponseEntity.ok(tokenService.refreshStatus(request));
    }

    // ✅ ENDPOINT DE TESTE DE AUTENTICAÇÃO
    @GetMapping(TEST_AUTH_ENDPOINT)
    public String testAuth(JwtAuthenticationToken token) {

        if (token == null) {
            return TOKEN_NULL_MESSAGE;
        }

        return AUTH_SUCCESS_MESSAGE + token.getName() +
               AUTHORITIES_MESSAGE + token.getAuthorities();
    }
}
