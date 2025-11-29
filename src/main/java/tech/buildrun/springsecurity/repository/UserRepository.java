package tech.buildrun.springsecurity.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import tech.buildrun.springsecurity.entities.User;

@Repository
public interface UserRepository extends JpaRepository<User,UUID> {

	Optional<User> findByUsername(String username);



}
