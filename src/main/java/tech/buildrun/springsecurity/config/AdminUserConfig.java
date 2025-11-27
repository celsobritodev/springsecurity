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

@Configuration
public class AdminUserConfig implements CommandLineRunner {
	
	private RoleRepository roleRepository;
	
	private UserRepository userRepository;
	
	private BCryptPasswordEncoder passwordEncoder;
	
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
		
		// ✅ CORREÇÃO: Extrair Role do Optional OU criar se não existir
        Role roleAdmin = roleRepository.findByName("ADMIN")
            .orElseGet(() -> {
                // Criar role ADMIN se não existir
                Role newRole = new Role();
                newRole.setName("ADMIN");
                Role savedRole = roleRepository.save(newRole);
                System.out.println("✅ Role ADMIN criada no banco!");
                return savedRole;
            });
		
		
		var userAdmin = userRepository.findByUsername("admin");
		
		userAdmin.ifPresentOrElse(
				user -> { 
					  System.out.println("admin já existe!");
				},
				()-> {
					var user = new User();
					user.setUsername("admin");
					user.setPassword(passwordEncoder.encode("123"));
					user.setRoles(Set.of(roleAdmin));
					userRepository.save(user);
					System.out.println("✅ Admin criado com sucesso!");
				}
				);
		
				
		
	}

}
