package tech.buildrun.springsecurity.services;

import java.util.List;
import java.util.Set;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import tech.buildrun.springsecurity.controller.dto.CreateUserDto;
import tech.buildrun.springsecurity.entities.Role;
import tech.buildrun.springsecurity.entities.User;
import tech.buildrun.springsecurity.repository.RoleRepository;
import tech.buildrun.springsecurity.repository.UserRepository;

@Service
public class UserService {

    private static final String ROLE_BASIC = Role.UserRole.BASIC.name();

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public void createUser(CreateUserDto dto) {

        if (userRepository.findByUsername(dto.username()).isPresent()) {
            throw new RuntimeException("Usuário já existe.");
        }

        var basicRole = roleRepository.findByName(ROLE_BASIC)
                .orElseThrow(() -> new RuntimeException("Role basic não encontrada"));

        var user = new User();
        user.setUsername(dto.username());
        user.setPassword(passwordEncoder.encode(dto.password()));
        user.setRoles(Set.of(basicRole));

        userRepository.save(user);
    }

    public List<User> listUsers() {
        return userRepository.findAll();
    }
}
