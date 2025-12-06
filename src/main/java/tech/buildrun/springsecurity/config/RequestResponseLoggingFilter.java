package tech.buildrun.springsecurity.config;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestResponseLoggingFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        System.out.println("\n=== INÍCIO REQUISIÇÃO ===");
        System.out.println("URI: " + req.getRequestURI());
        System.out.println("Method: " + req.getMethod());
        System.out.println("Authorization: " + req.getHeader("Authorization"));
        System.out.println("Query: " + req.getQueryString());

        long startTime = System.currentTimeMillis();

        try {
            chain.doFilter(request, response);
        } finally {
            long duration = System.currentTimeMillis() - startTime;

            int status = res.getStatus();
            String authHeader = req.getHeader("Authorization");
            String wwwAuth = res.getHeader("WWW-Authenticate");

            System.out.println("Status: " + status);

            // ✅ DETECÇÃO DE TOKEN EXPIRADO OU INVÁLIDO
            if (status == 401 && authHeader != null && authHeader.startsWith("Bearer ")) {

                if (wwwAuth != null && wwwAuth.toLowerCase().contains("expired")) {
                    System.out.println("⛔ TOKEN EXPIRADO: O access token enviado está expirado.");
                } else {
                    System.out.println("⛔ TOKEN INVÁLIDO: O access token enviado é inválido ou foi revogado.");
                }

            } else if (status == 403) {
                System.out.println("🚫 ACESSO NEGADO: Usuário autenticado sem permissão.");
            }

            System.out.println("Duração: " + duration + "ms");
            System.out.println("=== FIM REQUISIÇÃO ===\n");
        }
    }
}
