package com.ll.apigateway.filter;

import com.ll.apigateway.dto.RefreshTokenRequest;
import com.ll.apigateway.dto.TokenResponse;
import com.ll.apigateway.filter.AuthenticationFilter.Config;
import com.ll.apigateway.jwt.JwtUtil;
import com.ll.apigateway.service.TokenCacheService;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AuthenticationFilter extends AbstractGatewayFilterFactory<Config> {

  @Value("${services.auth.url}")
  private String authServiceUrl;

  // k6 테스트를 위한 테스트 모드 설정
  @Value("${test.mode:REDIS}")
  private String testMode; // COMPLEX, SIMPLE, REDIS

  // 복잡한 락 로직용 (기존 코드)
  private final ConcurrentHashMap<String, Mono<TokenResponse>> refreshingTokens = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, ReentrantLock> tokenLocks = new ConcurrentHashMap<>();

  private final JwtUtil jwtUtil;
  private final WebClient webClient;
  private final TokenCacheService tokenCacheService;

  // 공개 엔드포인트 목록
  private final List<String> openEndpoints = List.of(
      "/api/v1/auth/signup",
      "/api/v1/auth/login",
      "/api/v1/auth/logout"
  );

  public AuthenticationFilter(
      JwtUtil jwtUtil,
      WebClient.Builder webClientBuilder,
      TokenCacheService tokenCacheService) {
    super(Config.class);
    this.jwtUtil = jwtUtil;
    this.webClient = webClientBuilder.build();
    this.tokenCacheService = tokenCacheService;
  }

  @Override
  public GatewayFilter apply(Config config) {
    return (exchange, chain) -> {
      ServerHttpRequest request = exchange.getRequest();
      String path = request.getPath().value();

      // 공개 엔드포인트 체크
      if (isOpenEndpoint(path)) {
        return chain.filter(exchange);
      }

      String accessToken = extractAccessToken(exchange);

      // Access Token이 유효한 경우
      if (accessToken != null && jwtUtil.isValid(accessToken) && !jwtUtil.isExpired(accessToken)) {
        return addUserHeaders(exchange, chain, accessToken);
      }

      // Refresh Token으로 처리
      String refreshToken = extractRefreshToken(exchange);
      if (refreshToken == null) {
        return onError(exchange, "토큰 없음", HttpStatus.UNAUTHORIZED);
      }

      log.info("========================================================================================================================================");

      // 테스트 모드에 따라 다른 refresh 로직 사용
      return handleRefreshTokenByMode(exchange, chain, refreshToken);
    };
  }

  private boolean isOpenEndpoint(String path) {
    return openEndpoints.stream().anyMatch(path::startsWith);
  }

  private String extractAccessToken(ServerWebExchange exchange) {
    HttpCookie cookie = exchange.getRequest().getCookies().getFirst("accessToken");
    return cookie != null ? cookie.getValue() : null;
  }

  private String extractRefreshToken(ServerWebExchange exchange) {
    HttpCookie cookie = exchange.getRequest().getCookies().getFirst("refreshToken");
    return cookie != null ? cookie.getValue() : null;
  }

  private Mono<Void> addUserHeaders(ServerWebExchange exchange, GatewayFilterChain chain, String accessToken) {
    String username = jwtUtil.getUsernameFromToken(accessToken);
    Long userId = jwtUtil.getUserIdFromToken(accessToken);

    ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
        .header("X-User-ID", String.valueOf(userId))
        .header("X-Username", username)
        .build();

    return chain.filter(exchange.mutate().request(modifiedRequest).build());
  }

  private Mono<Void> handleRefreshTokenByMode(ServerWebExchange exchange, GatewayFilterChain chain, String refreshToken) {
    log.info("Using test mode: {}", testMode);

    switch (testMode.toUpperCase()) {
      case "COMPLEX":
        log.debug("Using COMPLEX locking logic for token refresh========================================");
        return refreshTokenWithComplexLocking(exchange, chain, refreshToken);
      case "SIMPLE":
        return refreshTokenSimple(exchange, chain, refreshToken);
      case "REDIS":
        log.debug("Using REDIS caching logic for token refresh========================================");
        return refreshTokenWithRedis(exchange, chain, refreshToken);
      default:
        log.warn("Unknown test mode: {}, falling back to COMPLEX", testMode);
        return refreshTokenWithComplexLocking(exchange, chain, refreshToken);
    }
  }

  // 모드 1: 복잡한 락 로직 (기존 코드)
  private Mono<Void> refreshTokenWithComplexLocking(ServerWebExchange exchange, GatewayFilterChain chain, String refreshToken) {
    log.debug("Using COMPLEX locking logic for token refresh");

    String tokenKey = generateTokenKey(refreshToken);

    // 이미 진행 중인 요청이 있는지 확인
    Mono<TokenResponse> cachedRefresh = refreshingTokens.get(tokenKey);
    if (cachedRefresh != null) {
      log.debug("Using cached token refresh request for token: {}", tokenKey);
      return cachedRefresh.flatMap(tokenResponse -> applyNewTokensAndContinue(exchange, chain, tokenResponse));
    }

    // 토큰별 락 획득
    ReentrantLock lock = tokenLocks.computeIfAbsent(tokenKey, k -> new ReentrantLock());
    boolean locked = lock.tryLock();
    if (!locked) {
      // 락 획득 실패 시 재시도 (짧은 대기 후)
      return Mono.delay(Duration.ofMillis(50))
          .then(refreshTokenWithComplexLocking(exchange, chain, refreshToken));
    }

    try {
      // 다시 확인 (락 획득 후 다른 스레드가 이미 처리했을 수 있음)
      cachedRefresh = refreshingTokens.get(tokenKey);
      if (cachedRefresh != null) {
        return cachedRefresh.flatMap(tokenResponse -> applyNewTokensAndContinue(exchange, chain, tokenResponse));
      }

      // 실제 리프레시 토큰 요청 생성
      Mono<TokenResponse> refreshRequest = webClient.post()
          .uri(authServiceUrl + "/api/v1/auth/refresh")
          .bodyValue(new RefreshTokenRequest(refreshToken))
          .retrieve()
          .bodyToMono(TokenResponse.class)
          .doOnSuccess(result -> log.debug("Token refreshed successfully"))
          .doOnError(error -> log.error("Token refresh failed", error))
          .cache();

      // 진행 중인 요청 맵에 추가
      refreshingTokens.put(tokenKey, refreshRequest);

      // 일정 시간 후 캐시에서 제거
      refreshRequest.doFinally(signal -> {
        Mono.delay(Duration.ofSeconds(10))
            .doOnSuccess(v -> {
              refreshingTokens.remove(tokenKey);
              tokenLocks.remove(tokenKey);
            })
            .subscribe();
      }).subscribe();

      return refreshRequest
          .flatMap(tokenResponse -> applyNewTokensAndContinue(exchange, chain, tokenResponse))
          .onErrorResume(e -> {
            log.error("Token refresh error: {}", e.getMessage());
            return onError(exchange, "토큰 갱신 중 오류 발생: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
          });
    } finally {
      lock.unlock();
    }
  }

  // 모드 2: 단순 로직 (락 제거)
  private Mono<Void> refreshTokenSimple(ServerWebExchange exchange, GatewayFilterChain chain, String refreshToken) {
    log.debug("Using SIMPLE logic for token refresh");

    return webClient.post()
        .uri(authServiceUrl + "/api/v1/auth/refresh")
        .bodyValue(new RefreshTokenRequest(refreshToken))
        .retrieve()
        .bodyToMono(TokenResponse.class)
        .timeout(Duration.ofSeconds(5))
        .flatMap(tokenResponse -> applyNewTokensAndContinue(exchange, chain, tokenResponse))
        .onErrorResume(e -> {
          log.error("Simple token refresh error: {}", e.getMessage());
          return onError(exchange, "토큰 갱신 실패", HttpStatus.UNAUTHORIZED);
        });
  }

  // 모드 3: Redis 캐싱 로직
  private Mono<Void> refreshTokenWithRedis(ServerWebExchange exchange, GatewayFilterChain chain, String refreshToken) {
    log.debug("Using REDIS caching logic for token refresh");

    return tokenCacheService.getOrRefreshToken(refreshToken)
        .flatMap(tokenResponse -> applyNewTokensAndContinue(exchange, chain, tokenResponse))
        .onErrorResume(e -> {
          log.error("Redis token refresh error: {}", e.getMessage());
          return onError(exchange, "Redis 토큰 갱신 실패", HttpStatus.UNAUTHORIZED);
        });
  }

  private Mono<Void> applyNewTokensAndContinue(ServerWebExchange exchange, GatewayFilterChain chain, TokenResponse tokenResponse) {
    ServerHttpResponse mutatedResponse = exchange.getResponse();

    // 새 토큰을 쿠키에 설정
    mutatedResponse.addCookie(
        ResponseCookie.from("accessToken", tokenResponse.getAccessToken())
            .httpOnly(true)
            .secure(true)
            .path("/")
            .maxAge(tokenResponse.getAccessTokenExpirationTime())
            .build()
    );
    mutatedResponse.addCookie(
        ResponseCookie.from("refreshToken", tokenResponse.getRefreshToken())
            .httpOnly(true)
            .secure(true)
            .path("/")
            .maxAge(60 * 60 * 24 * 7) // 7일
            .build()
    );

    // 요청별 고유 ID 생성
    String requestId = UUID.randomUUID().toString();

    // 헤더에 사용자 정보 추가
    ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
        .header("X-Request-ID", requestId)
        .header("X-User-ID", String.valueOf(jwtUtil.getUserIdFromToken(tokenResponse.getAccessToken())))
        .header("X-Username", jwtUtil.getUsernameFromToken(tokenResponse.getAccessToken()))
        .header("X-Test-Mode", testMode) // 테스트 모드 추가
        .build();

    return chain.filter(exchange.mutate().request(modifiedRequest).response(mutatedResponse).build());
  }

  private String generateTokenKey(String token) {
    String uniqueIdentifier = token.substring(0, Math.min(20, token.length())) + "-" + System.nanoTime();
    return Integer.toHexString(uniqueIdentifier.hashCode());
  }

  private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
    ServerHttpResponse response = exchange.getResponse();
    response.setStatusCode(status);
    log.error("Authentication error: {}", message);
    return response.setComplete();
  }

  public static class Config {
    // 필요한 경우 설정 속성 추가
  }
}