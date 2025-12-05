package tech.buildrun.springsecurity.config;

import tech.buildrun.springsecurity.entities.Role; // Ou seu pacote correto
import tech.buildrun.springsecurity.entities.User;

import java.util.Set;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import org.springframework.transaction.annotation.Transactional;
import tech.buildrun.springsecurity.repository.RoleRepository;
import tech.buildrun.springsecurity.repository.UserRepository;


//“Esse código roda automaticamente quando a aplicação Spring inicia.”
@Configuration
public class AdminUserConfig implements CommandLineRunner {
    
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    
    public AdminUserConfig(RoleRepository roleRepository,
                           UserRepository userRepository,
                           BCryptPasswordEncoder passwordEncoder) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    
    @Override
    @Transactional
    public void run(String... args) throws Exception {
        
       
        
        // ✅ CRIAR ROLE ADMIN
        Role roleAdmin = roleRepository.findByName("ADMIN")
            .orElseGet(() -> {
                Role newRole = new Role();
                newRole.setName("ADMIN");
                Role savedRole = roleRepository.save(newRole);
                System.out.println("✅ Role ADMIN criada no banco!");
                return savedRole;
            });
 
        
     // ✅ CRIAR ROLE BASIC
        Role roleBasic = roleRepository.findByName("BASIC")
            .orElseGet(() -> {
                Role newRole = new Role();
                newRole.setName("BASIC");
                Role savedRole = roleRepository.save(newRole);
                System.out.println("✅ Role BASIC criada no banco!");
                return savedRole;
            });
        
        
        // ✅ CRIAR USUÁRIO ADMIN
        var userAdmin = userRepository.findByUsername("admin");
        
        userAdmin.ifPresentOrElse(
            user -> { 
                System.out.println("✅ Admin já existe!");
            },
            () -> {
                var user = new User();
                user.setUsername("admin");
                user.setPassword(passwordEncoder.encode("123"));
                user.setRoles(Set.of(roleAdmin));
                userRepository.save(user);
                System.out.println("✅ Usuário 'admin' criado com sucesso!");
                System.out.println("👤 Username: admin");
                System.out.println("🔐 Password: 123");
                System.out.println("⚠️  ALTERE A SENHA PADRÃO!");
            }
        );
        
        
     // ✅ CRIAR USUÁRIO USER COM ROLE BASIC
        var userBasic = userRepository.findByUsername("user");
        
        userBasic.ifPresentOrElse(
            user -> { 
                System.out.println("✅ Usuário user já existe!");
            },
            () -> {
                var user = new User();
                user.setUsername("user");
                user.setPassword(passwordEncoder.encode("456"));
                user.setRoles(Set.of(roleBasic));
                userRepository.save(user);
                System.out.println("✅ Usuário 'user' criado com sucesso!");
                System.out.println("👤 Username: user");
                System.out.println("🔐 Password: 456");
                System.out.println("🎯 Role: BASIC");
            }
        );
        
        
        
        
        
    }
}