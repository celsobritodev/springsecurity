package tech.buildrun.springsecurity.controller;

import java.util.UUID;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import tech.buildrun.springsecurity.controller.dto.CreateTweetDto;
import tech.buildrun.springsecurity.controller.dto.FeedDto;
import tech.buildrun.springsecurity.controller.dto.FeedItemDto;
import tech.buildrun.springsecurity.entities.Role;
import tech.buildrun.springsecurity.entities.Tweet;
import tech.buildrun.springsecurity.repository.TweetRepository;
import tech.buildrun.springsecurity.repository.UserRepository;

@RestController
public class TweetController {

    // 🔥 CONSTANTES DO CONTROLLER
    private static final String FEED_ENDPOINT = "/feed";
    private static final String TWEETS_ENDPOINT = "/tweets";
    private static final String DELETE_TWEET_ENDPOINT = "/tweets/{id}";
    private static final String PARAM_PAGE = "page";
    private static final String PARAM_PAGE_SIZE = "pageSize";
    private static final String DEFAULT_PAGE = "0";
    private static final String DEFAULT_PAGE_SIZE = "10";
    private static final String SORT_FIELD = "creationTimestamp";
    private static final String ROLE_ADMIN = Role.UserRole.ADMIN.name();
    private static final String NOT_FOUND_MESSAGE = "Tweet not found";

    private final TweetRepository tweetRepository;
    private final UserRepository userRepository;

    public TweetController(UserRepository userRepository, TweetRepository tweetRepository) {
        this.userRepository = userRepository;
        this.tweetRepository = tweetRepository;
    }

   
    // lista tweets
    @GetMapping(FEED_ENDPOINT)
    public ResponseEntity<FeedDto> feed(
            @RequestParam(value = PARAM_PAGE, defaultValue = DEFAULT_PAGE) int page,
            @RequestParam(value = PARAM_PAGE_SIZE, defaultValue = DEFAULT_PAGE_SIZE) int pageSize,
            JwtAuthenticationToken token) {
        
        System.out.println("=== DEBUG /feed ===");
        System.out.println("Token recebido: " + (token != null ? "SIM" : "NÃO"));
        
        if (token != null) {
            System.out.println("Token Name (subject): " + token.getName());
            System.out.println("Token Principal: " + token.getPrincipal());
            System.out.println("Token Authorities: " + token.getAuthorities());
            System.out.println("Token Claims: " + token.getTokenAttributes());
            System.out.println("Token Scopes: " + token.getTokenAttributes().get("scope"));
        }
        
        // Resto do código original...
        var tweets = tweetRepository.findAll(
                PageRequest.of(page, pageSize, Sort.Direction.DESC, SORT_FIELD))
                .map(tweet -> new FeedItemDto(
                        tweet.getTweetId(),
                        tweet.getContent(),
                        tweet.getUser().getUsername()));

        System.out.println("Total de tweets encontrados: " + tweets.getTotalElements());
        System.out.println("=== FIM DEBUG /feed ===");
        
        return ResponseEntity.ok(
                new FeedDto(
                        tweets.getContent(),
                        page,
                        pageSize,
                        tweets.getTotalPages(),
                        tweets.getTotalElements()));
    }
    
    
    
    
    
    
    
    
    
    

    // cria tweets
    @PostMapping(TWEETS_ENDPOINT)
    public ResponseEntity<Void> createTweet(@RequestBody CreateTweetDto dto, JwtAuthenticationToken token) {
        var user = userRepository.findById(UUID.fromString(token.getName()));

        var tweet = new Tweet();
        tweet.setUser(user.get());
        tweet.setContent(dto.content());

        tweetRepository.save(tweet);

        return ResponseEntity.ok().build();
    }

    @DeleteMapping(DELETE_TWEET_ENDPOINT)
    public ResponseEntity<Void> deleteTweet(@PathVariable("id") Long tweetId, JwtAuthenticationToken token) {

        var user = userRepository.findById(UUID.fromString(token.getName()));

        var tweet = tweetRepository.findById(tweetId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, NOT_FOUND_MESSAGE));

        var isAdmin = user.get().getRoles()
                .stream()
                .anyMatch(role -> role.getName().equalsIgnoreCase(ROLE_ADMIN));

        if (isAdmin || tweet.getUser().getUserId().equals(UUID.fromString(token.getName()))) {
            tweetRepository.deleteById(tweetId);
            return ResponseEntity.ok().build();
        }

        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
}
