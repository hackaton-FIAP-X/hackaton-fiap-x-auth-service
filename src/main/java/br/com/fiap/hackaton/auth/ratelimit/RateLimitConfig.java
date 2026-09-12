package br.com.fiap.hackaton.auth.ratelimit;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(RedisProperties.class)
public class RateLimitConfig {

  @Bean(destroyMethod = "shutdown")
  public RedisClient loginRateLimitRedisClient(RedisProperties redisProperties) {
    RedisURI uri = RedisURI.create(redisProperties.getHost(), redisProperties.getPort());
    return RedisClient.create(uri);
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
