package com.ll.apigateway.config;

import com.ll.apigateway.filter.AuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class RouterConfig {

  private final AuthenticationFilter authFilter;

  @Value("${services.auth.url}")
  private String authServiceUrl;

  @Value("${services.member.url}")
  private String memberServiceUrl;

  @Value("${services.space.url}")
  private String spaceServiceUrl;

  @Value("${services.tech-interview.url}")
  private String techInterviewServiceUrl;

  @Value("${services.onlinejudge.url}")
  private String onlineJudgeServiceUrl;  // application.yml에 추가 필요


  @Value("${services.ai.url}")
  private String aiServiceUrl;


  @Bean
  public RouteLocator routes(RouteLocatorBuilder builder) {
    return builder.routes()

        // 인증 서비스 라우팅 (보호된 엔드포인트)
        .route("member-service", r -> r.path("/api/v1/auth/user")
            .filters(f -> f.filter(authFilter.apply(new AuthenticationFilter.Config())))
            .uri(authServiceUrl))

        // 인증 서비스 라우팅
        .route("auth-service", r -> r.path("/api/v1/auth/**")
            .filters(f -> f.rewritePath("/api/v1/auth/(?<segment>.*)", "/api/v1/auth/${segment}"))
            .uri(authServiceUrl))

        //social 로그인 라우팅
        .route("oauth-routes", r -> r.path("/oauth2/**", "/login/oauth2/**")
            .uri(authServiceUrl))

        // 회원 서비스 라우팅 (보호된 엔드포인트)
        .route("member-service", r -> r.path("/api/v1/members/**")
            .filters(f -> f.filter(authFilter.apply(new AuthenticationFilter.Config())))
            .uri(memberServiceUrl))

        // 스페이스 서비스 라우팅 (보호된 엔드포인트)
        .route("space-service", r -> r.path("/api/v1/space/**")
            .filters(f -> f.filter(authFilter.apply(new AuthenticationFilter.Config())))
            .uri(spaceServiceUrl))

        // 기술면접 서비스 라우팅 (보호된 엔드포인트)
        .route("techInterview-service", r -> r.path("/api/v1/tech-interview/**")
//            .filters(f -> f.rewritePath("/api/v1/tech-interview/(?<segment>.*)", "/api/v1/tech-interview/${segment}"))
            .filters(f -> f.filter(authFilter.apply(new AuthenticationFilter.Config())))
            .uri(techInterviewServiceUrl))

        // OnlineJudge 서비스 라우팅 (보호된 엔드포인트)
        .route("onlinejudge-service", r -> r.path("/api/v1/coding-test/**")
            .filters(f -> f.filter(authFilter.apply(new AuthenticationFilter.Config()))
            .rewritePath("/api/v1/coding-test/(?<segment>.*)", "/api/v1/coding-test/${segment}"))
//            .filters(f -> f.rewritePath("/api/v1/coding-test/(?<segment>.*)", "/api/v1/coding-test/${segment}"))
            .uri(onlineJudgeServiceUrl))

        // ai 서비스 라우팅 (보호된 엔드포인트)
        .route("techInterview-service", r -> r.path("/api/v1/ai/**")
            .filters(f -> f.rewritePath("/api/v1/ai/(?<segment>.*)", "/api/v1/ai/${segment}"))
//            .filters(f -> f.filter(authFilter.apply(new AuthenticationFilter.Config())))
            .uri(aiServiceUrl))

        // 필요한 다른 서비스 라우팅 추가

        .build();
  }
}