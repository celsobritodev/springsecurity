package tech.buildrun.springsecurity.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import tech.buildrun.springsecurity.entities.Role;



@Repository
public interface RoleRepository extends JpaRepository<Role,Long> {
	
	  // O método findById já vem do JpaRepository
    Optional<Role> findByName(String name); // opcional, se precisar

}
