package br.com.fiap.hackaton.auth.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;

import io.lettuce.core.RedisURI;

class RateLimitConfigTest {

  @Test
  void buildsPlainRedisUriFromHostAndPortWhenNoAuthOrSslConfigured() {
    RedisProperties redisProperties = new RedisProperties();
    redisProperties.setHost("redis-host");
    redisProperties.setPort(6380);

    RedisURI uri = RateLimitConfig.buildRedisUri(redisProperties);

    assertThat(uri.getHost()).isEqualTo("redis-host");
    assertThat(uri.getPort()).isEqualTo(6380);
    assertThat(uri.getPassword()).isNull();
    assertThat(uri.getUsername()).isNull();
    assertThat(uri.getDatabase()).isZero();
    assertThat(uri.isSsl()).isFalse();
  }

  @Test
  void honorsPasswordUsernameDatabaseAndSslFromRedisProperties() {
    RedisProperties redisProperties = new RedisProperties();
    redisProperties.setHost("redis-host");
    redisProperties.setPort(6380);
    redisProperties.setUsername("app-user");
    redisProperties.setPassword("s3cret");
    redisProperties.setDatabase(3);
    redisProperties.getSsl().setEnabled(true);

    RedisURI uri = RateLimitConfig.buildRedisUri(redisProperties);

    assertThat(uri.getUsername()).isEqualTo("app-user");
    assertThat(uri.getPassword()).isEqualTo("s3cret".toCharArray());
    assertThat(uri.getDatabase()).isEqualTo(3);
    assertThat(uri.isSsl()).isTrue();
  }

  @Test
  void appliesPasswordWithoutUsernameWhenOnlyPasswordIsConfigured() {
    RedisProperties redisProperties = new RedisProperties();
    redisProperties.setHost("redis-host");
    redisProperties.setPort(6380);
    redisProperties.setPassword("s3cret");

    RedisURI uri = RateLimitConfig.buildRedisUri(redisProperties);

    assertThat(uri.getPassword()).isEqualTo("s3cret".toCharArray());
  }
}
