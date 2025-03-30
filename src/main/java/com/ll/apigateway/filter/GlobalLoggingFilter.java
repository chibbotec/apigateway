package com.ll.apigateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class GlobalLoggingFilter implements GlobalFilter, Ordered {

  private static final Logger log = LoggerFactory.getLogger(GlobalLoggingFilter.class);

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    ServerHttpRequest request = exchange.getRequest();

    // 요청 정보 로깅
    log.info("===== Request Received =====");
    log.info("Method: {}", request.getMethod());
    log.info("Path: {}", request.getPath());
    log.info("URI: {}", request.getURI());
    log.info("Remote Address: {}", request.getRemoteAddress());

    // 헤더 정보 로깅
    log.info("Headers:");
    request.getHeaders().forEach((name, values) -> {
      log.info("  {}: {}", name, values);
    });

    // 쿼리 파라미터 로깅
    log.info("Query Params:");
    request.getQueryParams().forEach((name, values) -> {
      log.info("  {}: {}", name, values);
    });

    // 쿠키 정보 로깅
    log.info("Cookies: {}", request.getCookies());

    // 요청 처리 후 응답 로깅
    return chain.filter(exchange)
        .doOnSuccess(aVoid -> {
          log.info("===== Response Status =====");
          log.info("Status: {}", exchange.getResponse().getStatusCode());
          log.info("Response Headers:");
          exchange.getResponse().getHeaders().forEach((name, values) -> {
            log.info("  {}: {}", name, values);
          });
        })
        .doOnError(throwable -> {
          log.error("===== Error Processing Request =====");
          log.error("Error: {}", throwable.getMessage(), throwable);
        });
  }

  @Override
  public int getOrder() {
    // 다른 필터보다 먼저 실행되도록 높은 우선순위 설정
    return -1;
  }
}