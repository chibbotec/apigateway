package com.ll.apigateway.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;


@Component
@Slf4j
public class JwtUtil {

  private final Key key;
  private final ObjectMapper objectMapper = new ObjectMapper();

  public JwtUtil(@Value("${custom.jwt.secretKey}")String secret) {
    String keyBase64Encoded = Base64.getEncoder().encodeToString(secret.getBytes());
    this.key = Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());
  }

  public boolean isValid(String token) {
    try {
      // 토큰 파싱
      Jwts.parserBuilder()
          .setSigningKey(key)
          .build()
          .parseClaimsJws(token);
      return true;
    } catch (ExpiredJwtException e) {
      // 만료된 토큰은 여기서 처리되지만, 이 메서드에서는 유효한 것으로 간주
      return true;
    } catch (JwtException | IllegalArgumentException e) {
      // 기타 다른 JWT 예외는 유효하지 않은 것으로 간주
      return false;
    }
  }

//  public boolean isValid(String token) {
//    try {
//      Jwts.parserBuilder()
//          .setSigningKey(key)
//          .build()
//          .parseClaimsJws(token);
//      return true;
//    } catch (JwtException | IllegalArgumentException e) {
//      return false;
//    }
//  }

  public boolean isExpired(String token) {
    try {
      Date expiration = getClaims(token).getExpiration();
      return expiration.before(new Date());
    } catch (JwtException | IllegalArgumentException e) {
      return true;
    }
  }

  public Claims getClaims(String token) {
    return Jwts.parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(token)
        .getBody();
  }

  public String getSessionIdFromToken(String token) {
    Map<String, Object> payloadBody = getPayloadBody(token);
    // 세션 ID가 없는 기존 토큰을 위한 예외 처리
    return payloadBody.containsKey("sessionId") ?
        (String) payloadBody.get("sessionId") :
        UUID.randomUUID().toString(); // 없으면 새로 생성
  }


  @SuppressWarnings("unchecked")
  public Map<String, Object> getPayloadBody(String token) {
    try {
      Claims claims = getClaims(token);
      String bodyJson = claims.get("body", String.class);

      try {
        return objectMapper.readValue(bodyJson, Map.class);
      } catch (JsonProcessingException e) {
        log.error("JSON 파싱 오류: ", e);
        throw new RuntimeException("토큰 페이로드 처리 오류", e);
      }
    } catch (Exception e) {
      log.error("토큰 페이로드 추출 오류: ", e);
      // 빈 맵을 반환하여 NPE 방지
      return Map.of();
    }
  }

  public String getUsernameFromToken(String token) {
    Map<String, Object> payloadBody = getPayloadBody(token);
    return (String) payloadBody.get("username");
  }

  public Long getUserIdFromToken(String token) {
    Map<String, Object> payloadBody = getPayloadBody(token);
    Number id = (Number) payloadBody.get("id");
    return id.longValue();
  }
}