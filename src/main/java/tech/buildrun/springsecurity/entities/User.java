package tech.buildrun.springsecurity.entities;

import java.util.Set;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;

import jakarta.persistence.*;
import tech.buildrun.springsecurity.controller.dto.LoginRequest;

@Entity
@Table(name = "tb_users")
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	@Column(name = "user_id")
	private UUID userId;

	@Column(unique = true, nullable = false)
	private String username;

	@Column(nullable = false)
	private String password;

	// um usuario podera ter varias roles
	// varias roles vao estar associadas a diversos usuarios
	// teremos uma tabela associativa entre tabela usuario e tabela roles
	@ManyToMany(fetch= FetchType.EAGER)
	@JoinTable(name = "tb_users_roles", // nome da tabela associativa
			joinColumns = @JoinColumn(name = "user_id"),
			inverseJoinColumns = @JoinColumn(name = "role_id"))
	private Set<Role> roles;

	public UUID getUserId() {
		return userId;
	}

	public void setUserId(UUID userId) {
		this.userId = userId;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Set<Role> getRoles() {
		return roles;
	}

	public void setRoles(Set<Role> roles) {
		this.roles = roles;
	}
	
	
	public boolean isLoginCorrect(LoginRequest loginRequest, PasswordEncoder passwordEncoder) {
		return passwordEncoder.matches(loginRequest.password(),this.password);
	}
	
	
	

}
