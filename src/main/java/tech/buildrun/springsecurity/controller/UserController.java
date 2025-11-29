package tech.buildrun.springsecurity.controller;




import java.util.List;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;



import tech.buildrun.springsecurity.controller.dto.CreateUserDto;
import tech.buildrun.springsecurity.entities.Role;
import tech.buildrun.springsecurity.entities.User;
import tech.buildrun.springsecurity.repository.RoleRepository;
import tech.buildrun.springsecurity.repository.UserRepository;

@RestController
public class UserController {

    // 🔥 CONSTANTES DO CONTROLLER
    private static final String USERS_ENDPOINT = "/users";
    private static final String ERROR_USER_EXISTS = "User already exists";
    private static final String ERROR_ROLE_NOT_FOUND = "Basic role not found";
    private static final String ROLE_BASIC = Role.UserRole.BASIC.name();
    private static final String REQUIRED_SCOPE_ADMIN = "hasAuthority('SCOPE_ADMIN')";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public UserController(UserRepository userRepository,
                          RoleRepository roleRepository,
                          BCryptPasswordEncoder passwordEncoder) {

        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    @PostMapping(USERS_ENDPOINT)
    public ResponseEntity<Void> newUser(@RequestBody CreateUserDto dto) {

        var basicRole = roleRepository.findByName(ROLE_BASIC);

        var userFromDb = userRepository.findByUsername(dto.username());

        if (userFromDb.isPresent()) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_CONTENT, ERROR_USER_EXISTS);
        }

        if (basicRole.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, ERROR_ROLE_NOT_FOUND);
        }

        var user = new User();
        user.setUsername(dto.username());
        user.setPassword(passwordEncoder.encode(dto.password()));
        user.setRoles(Set.of(basicRole.get()));

        userRepository.save(user);

        return ResponseEntity.ok().build();
    }

    @GetMapping(USERS_ENDPOINT)
    @PreAuthorize(REQUIRED_SCOPE_ADMIN)
    public ResponseEntity<List<User>> listUsers() {
        var users = userRepository.findAll();
        return ResponseEntity.ok(users);
    }
}
