package br.com.fiap.hackaton.auth.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.function.Supplier;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;

@Testcontainers
class LazyLoginRateLimitProxyManagerTest {

  @Container
  static GenericContainer<?> redis =
      new GenericContainer<>(DockerImageName.parse("redis:7-alpine")).withExposedPorts(6379);

  private RedisClient redisClient;

  @AfterEach
  void shutdownClient() {
    if (redisClient != null) {
      redisClient.shutdown();
    }
  }

  @Test
  void connectsLazilyAndReusesTheSameProxyManagerAcrossCalls() {
    redisClient = RedisClient.create(RedisURI.create(redis.getHost(), redis.getMappedPort(6379)));
    LazyLoginRateLimitProxyManager lazyProxyManager =
        new LazyLoginRateLimitProxyManager(redisClient);

    ProxyManager<String> first = lazyProxyManager.get();
    ProxyManager<String> second = lazyProxyManager.get();

    assertThat(first).isSameAs(second);

    Supplier<BucketConfiguration> configuration =
        () ->
            BucketConfiguration.builder()
                .addLimit(Bandwidth.simple(1, Duration.ofMinutes(1)))
                .build();
    Bucket bucket = first.getProxy("lazy-proxy-manager-test:" + System.nanoTime(), configuration);

    assertThat(bucket.tryConsume(1)).isTrue();
    assertThat(bucket.tryConsume(1)).isFalse();
  }

  @Test
  void throwsWhenRedisIsUnreachable() {
    redisClient = RedisClient.create(RedisURI.create("localhost", 1));
    LazyLoginRateLimitProxyManager lazyProxyManager =
        new LazyLoginRateLimitProxyManager(redisClient);

    assertThatThrownBy(lazyProxyManager::get).isInstanceOf(RuntimeException.class);
  }

  @Test
  void failsFastWithoutReconnectingWithinTheBackoffWindowAfterAFailure() {
    RedisURI unreachableUri =
        RedisURI.Builder.redis("localhost", 1).withTimeout(Duration.ofSeconds(2)).build();
    redisClient = RedisClient.create(unreachableUri);
    LazyLoginRateLimitProxyManager lazyProxyManager =
        new LazyLoginRateLimitProxyManager(redisClient);

    // First call attempts the real connection and fails, recording the failure timestamp.
    assertThatThrownBy(lazyProxyManager::get).isInstanceOf(RuntimeException.class);

    // A second call within the backoff window must short-circuit rather than retry the
    // full connection attempt: it should return in well under the connect/command timeout
    // configured on the client above, proving no new connection was attempted.
    long start = System.nanoTime();
    assertThatThrownBy(lazyProxyManager::get).isInstanceOf(RuntimeException.class);
    long elapsedMillis = Duration.ofNanos(System.nanoTime() - start).toMillis();

    assertThat(elapsedMillis).isLessThan(500);
  }
}
