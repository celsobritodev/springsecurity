package tech.buildrun.springsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import tech.buildrun.springsecurity.entities.Tweet;



@Repository
public interface TweetRepository extends JpaRepository<Tweet,Long> {

}
