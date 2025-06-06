package com.ll.apigateway.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ll.apigateway.dto.RefreshTokenRequest;
import com.ll.apigateway.dto.TokenResponse;
import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
@Slf4j
public class TokenCacheService {

  private final ReactiveRedisTemplate<String, Object> redisTemplate;
  private final WebClient webClient;
  private final ObjectMapper objectMapper;

  @Value("${services.auth.url}")
  private String authServiceUrl;

  public TokenCacheService(ReactiveRedisTemplate<String, Object> redisTemplate,
      WebClient.Builder webClientBuilder, ObjectMapper objectMapper) {
    this.redisTemplate = redisTemplate;
    this.webClient = webClientBuilder.build();
    this.objectMapper = objectMapper;
  }

  public Mono<TokenResponse> getOrRefreshToken(String refreshToken) {
    String cacheKey = "refresh_token:" + hashToken(refreshToken);
    String lockKey = "refresh_lock:" + hashToken(refreshToken);

    // 1. 캐시에서 확인
    return redisTemplate.opsForValue().get(cacheKey)
        .cast(TokenResponse.class)
        .switchIfEmpty(
            // 2. 캐시 미스 → 분산 락으로 중복 요청 방지
            acquireDistributedLock(lockKey)
                .flatMap(lockAcquired -> {
                  if (lockAcquired) {
                    return refreshTokenFromAuth(refreshToken)
                        .doOnSuccess(tokenResponse ->
                            // 3. 결과를 캐시에 저장 (1분 TTL)
                            cacheTokenResponse(cacheKey, tokenResponse).subscribe())
                        .doFinally(signal ->
                            // 4. 락 해제
                            releaseLock(lockKey).subscribe());
                  } else {
                    // 락 획득 실패 → 짧은 대기 후 재시도
                    return Mono.delay(Duration.ofMillis(50))
                        .then(getOrRefreshToken(refreshToken));
                  }
                })
        );
  }

  private Mono<TokenResponse> refreshTokenFromAuth(String refreshToken) {
    return webClient.post()
        .uri(authServiceUrl + "/api/v1/auth/refresh")
        .bodyValue(new RefreshTokenRequest(refreshToken))
        .retrieve()
        .bodyToMono(TokenResponse.class)
        .timeout(Duration.ofSeconds(3))
        .doOnSuccess(response -> log.debug("Token refreshed from auth service"))
        .doOnError(error -> log.error("Auth service call failed", error));
  }

  private Mono<Boolean> acquireDistributedLock(String lockKey) {
    return redisTemplate.opsForValue()
        .setIfAbsent(lockKey, "locked", Duration.ofSeconds(10)) // 10초 TTL
        .defaultIfEmpty(false);
  }

  private Mono<Boolean> releaseLock(String lockKey) {
    return redisTemplate.opsForValue().delete(lockKey);
  }

  private Mono<Boolean> cacheTokenResponse(String cacheKey, TokenResponse tokenResponse) {
    return redisTemplate.opsForValue()
        .set(cacheKey, tokenResponse, Duration.ofMinutes(1));
  }

  private String hashToken(String token) {
    return Integer.toHexString(token.hashCode());
  }
}