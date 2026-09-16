package br.com.fiap.hackaton.auth.ratelimit;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.lettuce.core.ClientOptions;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.SocketOptions;

@Configuration
@EnableConfigurationProperties(RedisProperties.class)
public class RateLimitConfig {

  // This is a login-path rate limiter, not a bulk data path: a fast-failing connection lets the
  // filter fall back open (allow the request) quickly instead of blocking a shared Tomcat
  // request thread for the default 10s connect / 60s command timeouts during a Redis outage.
  private static final Duration CONNECT_TIMEOUT = Duration.ofMillis(300);
  private static final Duration COMMAND_TIMEOUT = Duration.ofSeconds(1);

  @Bean(destroyMethod = "shutdown")
  public RedisClient loginRateLimitRedisClient(RedisProperties redisProperties) {
    RedisClient redisClient = RedisClient.create(buildRedisUri(redisProperties));
    ClientOptions clientOptions =
        ClientOptions.builder()
            .socketOptions(SocketOptions.builder().connectTimeout(CONNECT_TIMEOUT).build())
            .build();
    redisClient.setOptions(clientOptions);
    return redisClient;
  }

  /**
   * Builds the {@link RedisURI} used for the login rate limiter connection, honoring
   * host/port/database/credentials/SSL from {@link RedisProperties} so a real deployment with a
   * managed, authenticated Redis does not silently fail to connect. Package-private and static so
   * it can be unit-tested without a Spring context.
   */
  static RedisURI buildRedisUri(RedisProperties redisProperties) {
    RedisURI.Builder uriBuilder =
        RedisURI.Builder.redis(redisProperties.getHost(), redisProperties.getPort())
            .withTimeout(COMMAND_TIMEOUT)
            .withDatabase(redisProperties.getDatabase());

    if (redisProperties.getSsl() != null && redisProperties.getSsl().isEnabled()) {
      uriBuilder.withSsl(true);
    }

    String username = redisProperties.getUsername();
    String password = redisProperties.getPassword();
    if (StringUtils.hasText(password)) {
      if (StringUtils.hasText(username)) {
        uriBuilder.withAuthentication(username, password.toCharArray());
      } else {
        uriBuilder.withPassword(password.toCharArray());
      }
    }

    return uriBuilder.build();
  }

  @Bean
  public FilterRegistrationBean<LoginRateLimitFilter> loginRateLimitFilterRegistration(
      RedisClient loginRateLimitRedisClient,
      ObjectMapper objectMapper,
      @Value("${app.security.rate-limit.login.capacity:10}") int capacity,
      @Value("${app.security.rate-limit.login.window-seconds:60}") int windowSeconds) {
    LazyLoginRateLimitProxyManager lazyProxyManager =
        new LazyLoginRateLimitProxyManager(loginRateLimitRedisClient);
    LoginRateLimitFilter filter =
        new LoginRateLimitFilter(lazyProxyManager::get, objectMapper, capacity, windowSeconds);

    FilterRegistrationBean<LoginRateLimitFilter> registration = new FilterRegistrationBean<>();
    registration.setFilter(filter);
    registration.addUrlPatterns("/auth/login");
    return registration;
  }
}
