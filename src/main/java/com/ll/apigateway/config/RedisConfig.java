package com.ll.apigateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
@EnableRedisRepositories
public class RedisConfig {

  @Bean
  public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
    RedisTemplate<String, Object> template = new RedisTemplate<>();
    template.setConnectionFactory(connectionFactory);
    template.setKeySerializer(new StringRedisSerializer());
    template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
    return template;
  }

  @Bean
  public ReactiveRedisTemplate<String, Object> reactiveRedisTemplate(ReactiveRedisConnectionFactory factory) {
    RedisSerializationContext<String, Object> serializationContext = RedisSerializationContext
        .<String, Object>newSerializationContext()
        .key(StringRedisSerializer.UTF_8)
        .hashKey(StringRedisSerializer.UTF_8)  // 이 부분이 누락되어 있었음
        .value(new GenericJackson2JsonRedisSerializer())
        .hashValue(new GenericJackson2JsonRedisSerializer())  // 이 부분도 추가
        .build();

    return new ReactiveRedisTemplate<>(factory, serializationContext);
  }
}