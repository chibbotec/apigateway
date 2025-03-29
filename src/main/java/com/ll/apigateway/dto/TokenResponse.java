package com.ll.apigateway.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenResponse {
  private String username;
  private String accessToken;
  private String refreshToken;
  private long accessTokenExpirationTime;
}