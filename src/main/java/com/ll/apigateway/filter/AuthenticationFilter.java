package com.ll.apigateway.filter;

import com.ll.apigateway.dto.RefreshTokenRequest;
import com.ll.apigateway.dto.TokenResponse;
import com.ll.apigateway.filter.AuthenticationFilter.Config;
import com.ll.apigateway.jwt.JwtUtil;
import java.time.Duration;
import java.util.List;
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

  // 진행 중인 리프레시 토큰 요청을 추적하는 맵
  private final ConcurrentHashMap<String, Mono<TokenResponse>> refreshingTokens = new ConcurrentHashMap<>();
  // 리프레시 토큰별 락
  private final ConcurrentHashMap<String, ReentrantLock> tokenLocks = new ConcurrentHashMap<>();

  private final JwtUtil jwtUtil;
  private final WebClient webClient;

  // 공개 엔드포인트 목록 (인증이 필요하지 않은 경로)
  private final List<String> openEndpoints = List.of(
      "/api/v1/auth/signup",
      "/api/v1/auth/signup",
      "/api/v1/auth/login",
      "/api/v1/auth/logout"
  );

  public AuthenticationFilter(JwtUtil jwtUtil, WebClient.Builder webClientBuilder) {
    super(Config.class);
    this.jwtUtil = jwtUtil;
    this.webClient = webClientBuilder.build();
  }

  @Override
  public GatewayFilter apply(Config config) {
    return (exchange, chain) -> {
      ServerHttpRequest request = exchange.getRequest();
      String path = request.getPath().value();

      // 공개 엔드포인트는 인증 필요 없음
      if (openEndpoints.stream().anyMatch(path::startsWith)) {
        return chain.filter(exchange);
      }

      // 쿠키에서 토큰 추출
      String accessToken = extractAccessToken(exchange);
      if (accessToken == null || accessToken.isBlank()) {
        return onError(exchange, "토큰이 없습니다.", HttpStatus.UNAUTHORIZED);
      }

      // 토큰 검증
      if (!jwtUtil.isValid(accessToken)) {
        return onError(exchange, "유효하지 않은 토큰입니다.", HttpStatus.UNAUTHORIZED);
      }

      // 토큰 만료 확인
      if (jwtUtil.isExpired(accessToken)) {
        // 리프레시 토큰 추출
        HttpCookie refreshCookie = exchange.getRequest().getCookies().getFirst("refreshToken");
        if (refreshCookie == null) {
          return onError(exchange, "액세스 토큰이 만료되고 리프레시 토큰이 없습니다.", HttpStatus.UNAUTHORIZED);
        }

        String refreshToken = refreshCookie.getValue();

        // 리프레시 토큰으로 새 토큰 발급 요청 (WebClient 사용)
        return refreshTokenAndContinue(exchange, chain, refreshToken);
      }

      // 인증된 사용자 정보를 헤더에 추가
      String username = jwtUtil.getUsernameFromToken(accessToken);
      Long userId = jwtUtil.getUserIdFromToken(accessToken);

      // 헤더에 사용자 정보 추가 (백엔드 서비스에서 사용할 수 있도록)
      ServerHttpRequest modifiedRequest = request.mutate()
          .header("X-User-ID", String.valueOf(userId))
          .header("X-Username", username)
          .build();

      // 수정된 요청으로 체인 계속 진행
      return chain.filter(exchange.mutate().request(modifiedRequest).build());
    };
  }

  private String extractAccessToken(ServerWebExchange exchange) {
    HttpCookie cookie = exchange.getRequest().getCookies().getFirst("accessToken");
    return cookie != null ? cookie.getValue() : null;
  }

   // 리프레시 토큰 처리 메소드
//  private Mono<Void> refreshTokenAndContinue(ServerWebExchange exchange, GatewayFilterChain chain, String refreshToken) {
//    return webClient.post()
//        .uri(authServiceUrl+"/api/v1/auth/refresh")
//        .bodyValue(new RefreshTokenRequest(refreshToken))
//        .exchange()
//        .flatMap(response -> {
//          log.debug("Refresh token response: {}", response.statusCode());
//          if (response.statusCode().is2xxSuccessful()) {
//            return response.bodyToMono(TokenResponse.class)
//                .flatMap(tokenResponse -> {
//                  // 새 토큰을 쿠키에 설정
//                  ServerHttpResponse mutatedResponse = exchange.getResponse();
//                  mutatedResponse.addCookie(
//                      ResponseCookie.from("accessToken", tokenResponse.getAccessToken())
//                          .httpOnly(true)
//                          .secure(true)
//                          .path("/")
//                          .maxAge(tokenResponse.getAccessTokenExpirationTime())
//                          .build()
//                  );
//                  mutatedResponse.addCookie(
//                      ResponseCookie.from("refreshToken", tokenResponse.getRefreshToken())
//                          .httpOnly(true)
//                          .secure(true)
//                          .path("/")
//                          .maxAge(60 * 60 * 24 * 7) // 7일
//                          .build()
//                  );
//
//                  // 새 토큰으로 헤더 설정
//                  ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
//                      .header("X-User-ID", String.valueOf(jwtUtil.getUserIdFromToken(tokenResponse.getAccessToken())))
//                      .header("X-Username", jwtUtil.getUsernameFromToken(tokenResponse.getAccessToken()))
//                      .build();
//
//                  // 원래 서비스로 요청 계속
//                  return chain.filter(
//                      exchange.mutate().request(modifiedRequest).response(mutatedResponse).build()
//                  );
//                });
//          } else {
//            return onError(exchange, "리프레시 토큰 갱신에 실패했습니다.", HttpStatus.UNAUTHORIZED);
//          }
//        })
//        .onErrorResume(e -> onError(exchange, "토큰 갱신 중 오류 발생: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR));
//  }


//  private Mono<Void> refreshTokenAndContinue(ServerWebExchange exchange, GatewayFilterChain chain, String refreshToken) {
//    log.debug("Attempting to refresh token: {}", refreshToken.substring(0, 10) + "...");
//    log.debug("Target URL: {}", authServiceUrl+"/api/v1/auth/refresh");
//
//    return webClient.post()
//        .uri(authServiceUrl+"/api/v1/auth/refresh")
//        .bodyValue(new RefreshTokenRequest(refreshToken))
//        .exchange()
//        .doOnSuccess(response -> {
//          log.debug("Successfully got response from refresh endpoint");
//        })
//        .doOnError(error -> {
//          log.error("Error occurred during refresh token request: {}", error.getMessage(), error);
//        })
//        .flatMap(response -> {
//          if (response.statusCode().is2xxSuccessful()) {
//            return response.bodyToMono(TokenResponse.class)
//                .flatMap(tokenResponse -> {
//                  // 새 토큰을 쿠키에 설정
//                  ServerHttpResponse mutatedResponse = exchange.getResponse();
//                  mutatedResponse.addCookie(
//                      ResponseCookie.from("accessToken", tokenResponse.getAccessToken())
//                          .httpOnly(true)
//                          .secure(true)
//                          .path("/")
//                          .maxAge(tokenResponse.getAccessTokenExpirationTime())
//                          .build()
//                  );
//                  mutatedResponse.addCookie(
//                      ResponseCookie.from("refreshToken", tokenResponse.getRefreshToken())
//                          .httpOnly(true)
//                          .secure(true)
//                          .path("/")
//                          .maxAge(60 * 60 * 24 * 7) // 7일
//                          .build()
//                  );
//
//                  // 새 토큰으로 헤더 설정
//                  ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
//                      .header("X-User-ID", String.valueOf(jwtUtil.getUserIdFromToken(tokenResponse.getAccessToken())))
//                      .header("X-Username", jwtUtil.getUsernameFromToken(tokenResponse.getAccessToken()))
//                      .build();
//
//                  // 원래 서비스로 요청 계속
//                  return chain.filter(
//                      exchange.mutate().request(modifiedRequest).response(mutatedResponse).build()
//                  );
//                });
//          } else {
//            return onError(exchange, "리프레시 토큰 갱신에 실ㅇㅁㄴㄹㅁㄴㅇ패했습니다.", HttpStatus.UNAUTHORIZED);
//          }
//
//        })
//        .onErrorResume(e -> {
//          log.error("Token refresh error details: {}", e.getMessage(), e);
//          return onError(exchange, "토큰 갱신 중 오류 발생: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
//        });
//  }
  private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
    ServerHttpResponse response = exchange.getResponse();
    response.setStatusCode(status);
    log.error("Authentication error: {}", message);
    return response.setComplete();
  }

  private Mono<Void> refreshTokenAndContinue(ServerWebExchange exchange, GatewayFilterChain chain, String refreshToken) {
    log.debug("Attempting to refresh token: {}", refreshToken.substring(0, 10) + "...");

    // 토큰의 간단한 해시 생성 (전체 토큰을 키로 사용하지 않기 위해)
    String tokenKey = generateTokenKey(refreshToken);

    // 이미 진행 중인 요청이 있는지 확인
    Mono<TokenResponse> cachedRefresh = refreshingTokens.get(tokenKey);
    if (cachedRefresh != null) {
      log.debug("Using cached token refresh request for token: {}", tokenKey);
      return cachedRefresh.flatMap(tokenResponse -> applyNewTokens(exchange, chain, tokenResponse));
    }

    // 토큰별 락 획득
    ReentrantLock lock = tokenLocks.computeIfAbsent(tokenKey, k -> new ReentrantLock());
    boolean locked = lock.tryLock();
    if (!locked) {
      // 락 획득 실패 시 재시도 (짧은 대기 후)
      return Mono.delay(Duration.ofMillis(50))
          .then(refreshTokenAndContinue(exchange, chain, refreshToken));
    }

    try {
      // 다시 확인 (락 획득 후 다른 스레드가 이미 처리했을 수 있음)
      cachedRefresh = refreshingTokens.get(tokenKey);
      if (cachedRefresh != null) {
        return cachedRefresh.flatMap(tokenResponse -> applyNewTokens(exchange, chain, tokenResponse));
      }

      // 실제 리프레시 토큰 요청 생성
      Mono<TokenResponse> refreshRequest = webClient.post()
          .uri(authServiceUrl + "/api/v1/auth/refresh")
          .bodyValue(new RefreshTokenRequest(refreshToken))
          .retrieve()
          .bodyToMono(TokenResponse.class)
          .doOnSuccess(result -> log.debug("Token refreshed successfully"))
          .doOnError(error -> log.error("Token refresh failed", error))
          .cache(); // 같은 Mono 인스턴스를 재사용하기 위해 캐싱

      // 진행 중인 요청 맵에 추가
      refreshingTokens.put(tokenKey, refreshRequest);

      // 일정 시간 후 캐시에서 제거 (캐시가 무한히 커지는 것 방지)
      refreshRequest.doFinally(signal -> {
        Mono.delay(Duration.ofSeconds(10))
            .doOnSuccess(v -> {
              refreshingTokens.remove(tokenKey);
              tokenLocks.remove(tokenKey);
            })
            .subscribe();
      }).subscribe();

      // 요청 실행 및 결과 처리
      return refreshRequest
          .flatMap(tokenResponse -> applyNewTokens(exchange, chain, tokenResponse))
          .onErrorResume(e -> {
            log.error("Token refresh error: {}", e.getMessage());
            return onError(exchange, "토큰 갱신 중 오류 발생: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
          });
    } finally {
      lock.unlock();
    }
  }

  // 새 토큰 적용 메서드 (코드 분리)
  private Mono<Void> applyNewTokens(ServerWebExchange exchange, GatewayFilterChain chain, TokenResponse tokenResponse) {
    ServerHttpResponse mutatedResponse = exchange.getResponse();
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

    // 새 토큰으로 헤더 설정
    ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
        .header("X-User-ID", String.valueOf(jwtUtil.getUserIdFromToken(tokenResponse.getAccessToken())))
        .header("X-Username", jwtUtil.getUsernameFromToken(tokenResponse.getAccessToken()))
        .build();

    // 원래 서비스로 요청 계속
    return chain.filter(
        exchange.mutate().request(modifiedRequest).response(mutatedResponse).build()
    );
  }

  // 토큰 키 생성 (보안을 위해 전체 토큰 대신 해시 사용)
  private String generateTokenKey(String token) {
    // 간단한 해시 계산 (또는 토큰의 일부만 사용)
    return Integer.toHexString(token.substring(0, Math.min(20, token.length())).hashCode());
  }



  public static class Config {
    // 필요한 경우 설정 속성 추가
  }
}