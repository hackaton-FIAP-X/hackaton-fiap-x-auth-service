package br.com.fiap.hackaton.auth.ratelimit;

import java.time.Duration;

import io.github.bucket4j.distributed.ExpirationAfterWriteStrategy;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisConnectionException;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.codec.ByteArrayCodec;
import io.lettuce.core.codec.RedisCodec;
import io.lettuce.core.codec.StringCodec;

class LazyLoginRateLimitProxyManager {

  // Once a connection attempt fails, skip retrying (and re-blocking the caller behind the
  // synchronized lock) for this long. Requests during the window fail fast so the fail-open
  // path in LoginRateLimitFilter can kick in immediately instead of queuing behind a slow
  // reconnect; a real reconnect attempt is retried again once the window elapses, so the
  // filter recovers automatically once Redis comes back.
  private static final long FAILURE_BACKOFF_MILLIS = Duration.ofSeconds(5).toMillis();

  private final RedisClient redisClient;
  private volatile ProxyManager<String> proxyManager;
  private volatile long lastFailureTimestamp = -1;

  LazyLoginRateLimitProxyManager(RedisClient redisClient) {
    this.redisClient = redisClient;
  }

  ProxyManager<String> get() {
    ProxyManager<String> existing = proxyManager;
    if (existing != null) {
      return existing;
    }

    long lastFailure = lastFailureTimestamp;
    if (lastFailure >= 0 && System.currentTimeMillis() - lastFailure < FAILURE_BACKOFF_MILLIS) {
      throw new RedisConnectionException(
          "Skipping Redis connection attempt: last failure was within the backoff window");
    }

    synchronized (this) {
      if (proxyManager == null) {
        try {
          StatefulRedisConnection<String, byte[]> connection =
              redisClient.connect(RedisCodec.of(StringCodec.UTF8, ByteArrayCodec.INSTANCE));
          proxyManager =
              LettuceBasedProxyManager.builderFor(connection)
                  .withExpirationStrategy(
                      ExpirationAfterWriteStrategy.basedOnTimeForRefillingBucketUpToMax(
                          Duration.ofMinutes(10)))
                  .build();
        } catch (RuntimeException ex) {
          lastFailureTimestamp = System.currentTimeMillis();
          throw ex;
        }
      }
      return proxyManager;
    }
  }
}
