package tech.buildrun.springsecurity.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);
    
    private final JdbcTemplate jdbcTemplate;

    public DataInitializer(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void run(String... args) throws Exception {
        logger.info("=== INICIANDO CARGA DE DADOS INICIAIS ===");
        
        try {
            initializeRoles();
            logger.info("=== CARGA DE DADOS CONCLUÍDA COM SUCESSO ===");
        } catch (Exception e) {
            logger.error("❌ Erro durante carga de dados: {}", e.getMessage());
            // Não relançar a exceção para evitar falha na aplicação
        }
    }

    private void initializeRoles() {
        // SQL para PostgreSQL - ON CONFLICT DO NOTHING
        String sqlAdmin = """
            INSERT INTO tb_roles (role_id, name) 
            VALUES (1, 'ADMIN') 
            ON CONFLICT (role_id) DO NOTHING
            """;
            
        String sqlBasic = """
            INSERT INTO tb_roles (role_id, name) 
            VALUES (2, 'BASIC') 
            ON CONFLICT (role_id) DO NOTHING
            """;
        
        try {
            // Executar inserções
            jdbcTemplate.update(sqlAdmin);
            jdbcTemplate.update(sqlBasic);
            
            logger.info("✅ Roles verificadas/criadas com sucesso");
            
        } catch (Exception e) {
            logger.warn("⚠️ As roles podem já existir: {}", e.getMessage());
        }
    }
}