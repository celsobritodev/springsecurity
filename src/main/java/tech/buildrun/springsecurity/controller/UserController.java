package tech.buildrun.springsecurity.controller;




import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import tech.buildrun.springsecurity.controller.dto.CreateUserDto;
import tech.buildrun.springsecurity.entities.User;
import tech.buildrun.springsecurity.services.UserService;

@RestController
public class UserController {

    // ✅ CONSTANTES DE ENDPOINT
    private static final String USERS_ENDPOINT = "/users";

    // ✅ CONSTANTE DE AUTORIDADE
    private static final String ROLE_ADMIN = "hasAuthority('SCOPE_ADMIN')";

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping(USERS_ENDPOINT)
    public ResponseEntity<Void> newUser(@RequestBody CreateUserDto dto) {
        userService.createUser(dto);
        return ResponseEntity.ok().build();
    }

    @GetMapping(USERS_ENDPOINT)
    @PreAuthorize(ROLE_ADMIN)
    public ResponseEntity<List<User>> listUsers() {
        return ResponseEntity.ok(userService.listUsers());
    }
}
