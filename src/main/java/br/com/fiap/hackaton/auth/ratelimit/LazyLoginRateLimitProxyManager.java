package br.com.fiap.hackaton.auth.ratelimit;

import io.github.bucket4j.distributed.ExpirationAfterWriteStrategy;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.lettuce.core.RedisClient;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.codec.ByteArrayCodec;
import io.lettuce.core.codec.RedisCodec;
import io.lettuce.core.codec.StringCodec;
import java.time.Duration;

class LazyLoginRateLimitProxyManager {

  private final RedisClient redisClient;
  private volatile ProxyManager<String> proxyManager;

  LazyLoginRateLimitProxyManager(RedisClient redisClient) {
    this.redisClient = redisClient;
  }

  ProxyManager<String> get() {
    ProxyManager<String> existing = proxyManager;
    if (existing != null) {
      return existing;
    }
    synchronized (this) {
      if (proxyManager == null) {
        StatefulRedisConnection<String, byte[]> connection =
            redisClient.connect(RedisCodec.of(StringCodec.UTF8, ByteArrayCodec.INSTANCE));
        proxyManager =
            LettuceBasedProxyManager.builderFor(connection)
                .withExpirationStrategy(
                    ExpirationAfterWriteStrategy.basedOnTimeForRefillingBucketUpToMax(
                        Duration.ofMinutes(10)))
                .build();
      }
      return proxyManager;
    }
  }
}
