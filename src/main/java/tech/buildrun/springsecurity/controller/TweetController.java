package tech.buildrun.springsecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import tech.buildrun.springsecurity.controller.dto.CreateTweetDto;
import tech.buildrun.springsecurity.controller.dto.FeedDto;
import tech.buildrun.springsecurity.services.TweetService;

@RestController
public class TweetController {

    // ✅ CONSTANTES DE ENDPOINT
    private static final String FEED_ENDPOINT = "/feed";
    private static final String TWEETS_ENDPOINT = "/tweets";
    private static final String DELETE_TWEET_ENDPOINT = "/tweets/{id}";

    // ✅ CONSTANTES DE PARÂMETROS
    private static final String PARAM_PAGE = "page";
    private static final String PARAM_PAGE_SIZE = "pageSize";
    private static final String DEFAULT_PAGE = "0";
    private static final String DEFAULT_PAGE_SIZE = "10";

    // ✅ CONSTANTE DE AUTORIDADE
    private static final String ROLE_ADMIN = "SCOPE_ADMIN";

    private final TweetService tweetService;

    public TweetController(TweetService tweetService) {
        this.tweetService = tweetService;
    }

    @GetMapping(FEED_ENDPOINT)
    public ResponseEntity<FeedDto> feed(
            @RequestParam(value = PARAM_PAGE, defaultValue = DEFAULT_PAGE) int page,
            @RequestParam(value = PARAM_PAGE_SIZE, defaultValue = DEFAULT_PAGE_SIZE) int pageSize) {

        return ResponseEntity.ok(tweetService.listFeed(page, pageSize));
    }

    @PostMapping(TWEETS_ENDPOINT)
    public ResponseEntity<Void> createTweet(
            @RequestBody CreateTweetDto dto,
            JwtAuthenticationToken token) {

        tweetService.createTweet(
                dto,
                java.util.UUID.fromString(token.getName())
        );

        return ResponseEntity.ok().build();
    }

    @DeleteMapping(DELETE_TWEET_ENDPOINT)
    public ResponseEntity<Void> deleteTweet(
            @PathVariable Long id,
            JwtAuthenticationToken token) {

        boolean isAdmin = token.getAuthorities()
                .stream()
                .anyMatch(a -> a.getAuthority().equals(ROLE_ADMIN));

        tweetService.deleteTweet(
                id,
                java.util.UUID.fromString(token.getName()),
                isAdmin
        );

        return ResponseEntity.ok().build();
    }
}