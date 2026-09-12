package br.com.fiap.hackaton.auth.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.time.Duration;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.codec.ByteArrayCodec;
import io.lettuce.core.codec.RedisCodec;
import io.lettuce.core.codec.StringCodec;

@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(
    properties = {
      "app.security.rate-limit.login.capacity=3",
      "app.security.rate-limit.login.window-seconds=60"
    })
class LoginRateLimitIntegrationTest {

  @Container @ServiceConnection
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

  @Container
  static GenericContainer<?> redis =
      new GenericContainer<>(DockerImageName.parse("redis:7-alpine")).withExposedPorts(6379);

  @DynamicPropertySource
  static void redisProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.data.redis.host", redis::getHost);
    registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
  }

  @Autowired private MockMvc mockMvc;

  private static final String LOGIN_PAYLOAD =
      """
      {"email":"nao.existe@example.com","password":"QualquerSenha123"}
      """;

  @Test
  void allowsUpToCapacityThenRejectsWithRetryAfter() throws Exception {
    for (int attempt = 1; attempt <= 3; attempt++) {
      int status =
          mockMvc
              .perform(
                  post("/auth/login")
                      .contentType("application/json")
                      .header("X-Forwarded-For", "198.51.100.1")
                      .content(LOGIN_PAYLOAD))
              .andReturn()
              .getResponse()
              .getStatus();

      assertThat(status).isNotEqualTo(429);
    }

    var fourthAttempt =
        mockMvc
            .perform(
                post("/auth/login")
                    .contentType("application/json")
                    .header("X-Forwarded-For", "198.51.100.1")
                    .content(LOGIN_PAYLOAD))
            .andReturn()
            .getResponse();

    assertThat(fourthAttempt.getStatus()).isEqualTo(429);
    assertThat(fourthAttempt.getHeader("Retry-After")).isNotNull();
    assertThat(fourthAttempt.getContentAsString()).contains("Too many login attempts");
  }

  @Test
  void countsIndependentIpsSeparately() throws Exception {
    for (int attempt = 1; attempt <= 3; attempt++) {
      mockMvc.perform(
          post("/auth/login")
              .contentType("application/json")
              .header("X-Forwarded-For", "198.51.100.2")
              .content(LOGIN_PAYLOAD));
    }

    var otherIpAttempt =
        mockMvc
            .perform(
                post("/auth/login")
                    .contentType("application/json")
                    .header("X-Forwarded-For", "198.51.100.3")
                    .content(LOGIN_PAYLOAD))
            .andReturn()
            .getResponse();

    assertThat(otherIpAttempt.getStatus()).isNotEqualTo(429);
  }

  @Test
  void sharesTheCounterAcrossTwoIndependentReplicaConnections() {
    RedisClient replicaAClient =
        RedisClient.create(RedisURI.create(redis.getHost(), redis.getMappedPort(6379)));
    RedisClient replicaBClient =
        RedisClient.create(RedisURI.create(redis.getHost(), redis.getMappedPort(6379)));
    try {
      StatefulRedisConnection<String, byte[]> replicaAConnection =
          replicaAClient.connect(RedisCodec.of(StringCodec.UTF8, ByteArrayCodec.INSTANCE));
      StatefulRedisConnection<String, byte[]> replicaBConnection =
          replicaBClient.connect(RedisCodec.of(StringCodec.UTF8, ByteArrayCodec.INSTANCE));

      Supplier<BucketConfiguration> configuration =
          () ->
              BucketConfiguration.builder()
                  .addLimit(Bandwidth.simple(1, Duration.ofMinutes(1)))
                  .build();
      String sharedKey = "multi-replica-test:" + System.nanoTime();

      ProxyManager<String> replicaAProxyManager =
          LettuceBasedProxyManager.builderFor(replicaAConnection).build();
      ProxyManager<String> replicaBProxyManager =
          LettuceBasedProxyManager.builderFor(replicaBConnection).build();

      Bucket replicaABucket = replicaAProxyManager.getProxy(sharedKey, configuration);
      Bucket replicaBBucket = replicaBProxyManager.getProxy(sharedKey, configuration);

      assertThat(replicaABucket.tryConsume(1)).isTrue();
      assertThat(replicaBBucket.tryConsume(1)).isFalse();

      replicaAConnection.close();
      replicaBConnection.close();
    } finally {
      replicaAClient.shutdown();
      replicaBClient.shutdown();
    }
  }
}
