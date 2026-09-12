# AUTH-6: Login Rate Limit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Protect `POST /auth/login` with a configurable, Redis-backed rate limit (default 10 requests/minute per client IP) that responds `429` with a `Retry-After` header when exceeded, shares its counter across every `auth-service` replica, and fails open (allows the request) if Redis is unreachable.

**Architecture:** A `jakarta.servlet.Filter` (`LoginRateLimitFilter`), registered only for `/auth/login` via a `FilterRegistrationBean`, asks a lazily-connected Bucket4j `ProxyManager` (backed by Redis through Lettuce) to consume one token per request, keyed by client IP. Because the Redis connection is established lazily on first real use — not during Spring context startup — every existing test in this repo keeps working unmodified even without a Redis container.

**Tech Stack:** Java 21, Spring Boot 3.3.4, Bucket4j 8.14.0 (`bucket4j_jdk17-core`, `bucket4j_jdk17-lettuce`), Lettuce (`io.lettuce:lettuce-core`, version managed by the Spring Boot BOM: `6.3.2.RELEASE`), JUnit 5, Mockito (already available via `spring-boot-starter-test`), Testcontainers (`GenericContainer` for Redis — no dedicated Testcontainers Redis module exists).

**Spec:** `docs/superpowers/specs/2026-09-11-auth-6-login-rate-limit-design.md`

## Global Constraints

- Repo root: `/home/marcosjesus/fiap/hackaton-fiap-x-auth-service`. New package: `br.com.fiap.hackaton.auth.ratelimit`.
- Rate limits only `POST /auth/login`. Every request counts (success or failure), keyed by client IP (`X-Forwarded-For` first entry, else `HttpServletRequest.getRemoteAddr()`).
- Default limit: 10 requests / 60 seconds, configurable via `app.security.rate-limit.login.capacity` and `app.security.rate-limit.login.window-seconds` — read with plain `@Value(...:default)`, matching how `JwtKeyConfig`/`PasswordEncoderConfig` already read scalar config in this app (not a `@ConfigurationProperties` record — that pattern belongs to the `security-commons` autoconfiguration library, not this app).
- Exceeding the limit responds `429` with a `Retry-After` header (seconds) and a JSON body reusing the existing `br.com.fiap.hackaton.auth.web.ErrorResponse` record.
- Redis connection is lazy and per-request-guarded: `RedisClient.create(...)` never opens a socket; only `.connect(...)`, called inside a try/catch on first real use, does. Any failure there is caught and treated as fail-open (request allowed, `WARN` logged). This is what keeps every existing `@SpringBootTest` (none of which declare a Redis container) passing unmodified.
- `spring.autoconfigure.exclude` MUST list `RedisAutoConfiguration` and `RedisReactiveAutoConfiguration` — without this, Spring Boot's own `LettuceConnectionFactory` autoconfiguration attempts an eager connection at context startup and breaks every existing `@SpringBootTest`. `RedisProperties` is registered by hand via `@EnableConfigurationProperties(RedisProperties.class)` on `RateLimitConfig` since the autoconfiguration that normally does this is excluded.
- Bucket4j Maven coordinates: `com.bucket4j:bucket4j_jdk17-core:8.14.0` and `com.bucket4j:bucket4j_jdk17-lettuce:8.14.0` — this is Java 21, so the `_jdk17` artifact line (NOT the legacy unsuffixed `bucket4j-core`/`bucket4j-redis` coordinates, which are older releases). Explicit `io.lettuce:lettuce-core` dependency with no version (resolves to the Spring Boot 3.3.4 BOM's `6.3.2.RELEASE` — Bucket4j's Lettuce integration declares it `provided`, so the consumer must supply it).
- Formatting: Spotless with `googleJavaFormat` 1.23.0, `importOrder java,javax,org,com`, one alphabetically-sorted import block with no blank lines between groups (same as every existing file in this repo — do not manually insert blank-line import groups). Run `./mvnw spotless:apply` if `spotless:check` fails during `mvn verify`.
- Every new class gets a test. Each task ends green (`./mvnw test -pl . -Dtest=<TestClass>` for the fast loop, full `./mvnw test` at the end of the plan) before moving to the next task.
- Do not modify `security-commons/` — unrelated to this card.

---

## File Structure

```
docker-compose.yml                                            (modify: add redis service)
pom.xml                                                        (modify: add dependencies)
src/main/resources/application.yml                             (modify: add redis + rate-limit config)
src/main/java/br/com/fiap/hackaton/auth/ratelimit/
  ClientIpResolver.java
  LazyLoginRateLimitProxyManager.java
  LoginRateLimitFilter.java
  RateLimitConfig.java
src/test/java/br/com/fiap/hackaton/auth/ratelimit/
  ClientIpResolverTest.java
  LazyLoginRateLimitProxyManagerTest.java
  LoginRateLimitFilterTest.java
  LoginRateLimitIntegrationTest.java
```

Each `src/main` file has one responsibility: IP extraction, lazy Redis-backed proxy-manager construction, the filter's request-handling logic, and Spring wiring. `LoginRateLimitIntegrationTest` is the only test that exercises the whole stack together (real Redis, real HTTP filter chain, multi-replica proof).

---

### Task 1: Infrastructure and dependencies

**Files:**
- Modify: `docker-compose.yml`
- Modify: `pom.xml`
- Modify: `src/main/resources/application.yml`

**Interfaces:**
- Produces: a `redis` service reachable at `REDIS_HOST`/`REDIS_PORT` (docker-compose) or `localhost:6379` (local `mvn` runs), the Bucket4j/Lettuce/Redis Maven dependencies on the classpath, and the `app.security.rate-limit.login.*` / `spring.data.redis.*` / `spring.autoconfigure.exclude` keys in `application.yml` that later tasks read.

- [ ] **Step 1: Add the `redis` service to `docker-compose.yml`**

Edit `docker-compose.yml`, adding a new `redis` service alongside `postgres`, and new environment entries + a `depends_on` clause on `auth-service`:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    container_name: auth-service-postgres
    environment:
      - POSTGRES_DB=auth_service
      - POSTGRES_USER=auth_service
      - POSTGRES_PASSWORD=auth_service
    ports:
      - "5433:5432"
    volumes:
      - auth_service_postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U auth_service -d auth_service"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    container_name: auth-service-redis
    ports:
      - "6380:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  auth-service:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: FIAP-auth-service
    ports:
      - "8080:8080"
      - "5005:5005"
    volumes:
      - ./src:/app/src
      - ./pom.xml:/app/pom.xml
      - ~/.m2:/root/.m2
    environment:
      - SPRING_PROFILES_ACTIVE=dev
      - SPRING_DEVTOOLS_RESTART_ENABLED=true
      - SPRING_DEVTOOLS_LIVERELOAD_ENABLED=true
      - SPRING_DEVTOOLS_RESTART_POLL_INTERVAL=2s
      - SPRING_DEVTOOLS_RESTART_QUIET_PERIOD=1s
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_NAME=auth_service
      - DB_USER=auth_service
      - DB_PASSWORD=auth_service
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      # Disposable RSA dev keypair for JWT signing — throwaway, never reuse in a real environment
      - JWT_PRIVATE_KEY=MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC8lw1/LUio9/sSKCJfc2QIYMOlMOf5VTHS0968XrKgQ7fA/IsZIO9v7bph1+iOQMZxKt3DSSd28UKXbp1eNdC9eSPO3XVQdHvTupgt36579dTKgDDEPWV7+C6rNgpJN3qcnF5DAmOzEhPGRv0omI7TBrhZ3fxgMTZIDMyUxgeM65JSGuaE7suol5Q9zOxExxar8krYD082xNyCD0EBOBDyUdxQRl2G66x6C+iaTx2S2w0Q1ZnQQ21obxUX6uOh21huOdf8KhTr2mq6m59+9HuDwX9szSHvg/B6Jx9gym+YQhwuLdJU+w1pMrQlQWZkbzW8I95hswBMnpU2nUCwXelFAgMBAAECggEABqqdnYXvmu7Of0ElReksULzVmFH26/ITsCIxLh4i2QDLzr9JTiVt5q+pS6rNhl8fz1b2k9/9dyTmzQzp9ISZJmQmhzoo2s6N+gQPO7/mc8H9jahOZlbNRD6XrRGx92NGAEyUFcZQg+n7Ak1MHFKYPzluQYRUAYp7zWbhFyPmQcLv03J6RS0r8SDElro065yfw8BEV8/jode3fw3NzUiaoskcjNrPhBPuSCfxGG6n4dHWolQEQjwCHoBOPCPB6L7w+krGL5oyDnni1FRRQzBDX3LHZym6XMExSw+QlZgUD7K0AgTYon7hA28MJedCi0+Ff7Kd1wo8KQDpAeIT6t1wQQKBgQDkWi9o/+dYZl6Zer31kvs/3yqMXJsW7E8l0b/2/QHoHIYVLkuQfvrctfn3MdoJR34QX9BrlIDZkKybnpx1SVL/LnGqEYhZxkS603j0tYjT4B9ozb9y6o3igMdTg4thWlBZCQoWCc0W8wfGDeW6amKthV5FTNyzFp7WWccMIP1zWQKBgQDTbG5IvLX++c0V7Y0fv4yNdS8qQFiCEC+UfqkSIPinnQZrDNVo4+dqdhp/ZpHGhV8lohEyjVsbaUhlrmwwHQ+1kUmQJkL05x6kF459dhReXs86It6pXgCoW0JeMLa7dnAQRT0UQOtrj5Oo9VCSbJjbGrDys3A2BAG7wSoi7DKDzQKBgQCO44QBLwhjf4M4hN6y+Ssw14N3W0dMu8f3AV4evkjgJmEcheCQ5XQygciNjutBnTPcKShw+Pb7rRTlOAXtOlmuBjDn25q3mmJNiaCJd8LL2dWtrflbfjwUfMK9lnW0EGBwpkBic/Wao668ltumn4Vp0SehM6xyf/gaZwkvpMET2QKBgQCpBVFxcvQoYDn1otCkpfTOjfVj2McpS5lOJKgzZwqCrUUZRcxCq5gxAzQRz8UQqUU0h8kp2doRIu0O5Q92s3UAmaLuy7fRpAdZ9b8jS8fi3fbbKk9JpW3vKe338QfU/E2ApGm9DF1owwKwG1YLiSf2WfNGQ++cLz3XhQiTnLKRrQKBgQDRhlWNzP7KKssePEstxOiqBARrafylp2LmVc4LgTgvJhvgfxmckOjDBQb4Zya20Lo19VVyXcBLGC3HexXsYThBCL/bDm0PAfxSz6zgoRwZGeRv0UILHXMYUB9WbGa5fe9ixb6YwKNTH7kOT0/MIv/eAM81kCR9UFzJ0m005rjD9w==
      - JWT_PUBLIC_KEY=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvJcNfy1IqPf7EigiX3NkCGDDpTDn+VUx0tPevF6yoEO3wPyLGSDvb+26YdfojkDGcSrdw0kndvFCl26dXjXQvXkjzt11UHR707qYLd+ue/XUyoAwxD1le/guqzYKSTd6nJxeQwJjsxITxkb9KJiO0wa4Wd38YDE2SAzMlMYHjOuSUhrmhO7LqJeUPczsRMcWq/JK2A9PNsTcgg9BATgQ8lHcUEZdhuusegvomk8dktsNENWZ0ENtaG8VF+rjodtYbjnX/CoU69pqupuffvR7g8F/bM0h74PweicfYMpvmEIcLi3SVPsNaTK0JUFmZG81vCPeYbMATJ6VNp1AsF3pRQIDAQAB
      - PASSWORD_PEPPER=8ec6006e-a115-4e7f-b1bc-59d537a00085
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: unless-stopped

volumes:
  auth_service_postgres_data:
```

(Only the `redis` service block, the `REDIS_HOST`/`REDIS_PORT` environment lines, and the `redis` entry under `depends_on` are new — everything else above is unchanged, shown for context so the edit is unambiguous. The host port `6380` avoids colliding with any Redis a developer might already run locally on the default `6379`.)

- [ ] **Step 2: Validate the compose file**

Run: `docker compose -f docker-compose.yml config >/dev/null && echo OK`
Expected: `OK` (validates YAML syntax and variable interpolation; does not start containers)

- [ ] **Step 3: Add Maven dependencies to `pom.xml`**

Edit `pom.xml`, adding these three dependencies inside the existing `<dependencies>` block (after the Flyway dependencies, before the password-hashing dependencies, to keep the file's existing "grouped by concern with a comment" style):

```xml
        <!-- Rate limiting (Bucket4j + Redis) -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
        <dependency>
            <groupId>io.lettuce</groupId>
            <artifactId>lettuce-core</artifactId>
        </dependency>
        <dependency>
            <groupId>com.bucket4j</groupId>
            <artifactId>bucket4j_jdk17-core</artifactId>
            <version>8.14.0</version>
        </dependency>
        <dependency>
            <groupId>com.bucket4j</groupId>
            <artifactId>bucket4j_jdk17-lettuce</artifactId>
            <version>8.14.0</version>
        </dependency>
```

- [ ] **Step 4: Verify the project still compiles with the new dependencies**

Run: `./mvnw -q compile`
Expected: exits `0`, no output (no compilation errors, no dependency-resolution failures)

- [ ] **Step 5: Add Redis and rate-limit configuration to `application.yml`**

Edit `src/main/resources/application.yml`. Add a `spring.data.redis` block and `spring.autoconfigure.exclude` under the existing `spring:` key, and a new `app.security.rate-limit` block under the existing `app.security:` key:

```yaml
spring:
  application:
    name: auth-service
  mvc:
    log-resolved-exception: false
  datasource:
    url: jdbc:postgresql://${DB_HOST:localhost}:${DB_PORT:5432}/${DB_NAME:auth_service}
    username: ${DB_USER:auth_service}
    password: ${DB_PASSWORD:auth_service}
  jpa:
    open-in-view: false
    hibernate:
      ddl-auto: validate
  flyway:
    enabled: true
    locations: classpath:db/migration
  data:
    redis:
      host: ${REDIS_HOST:localhost}
      port: ${REDIS_PORT:6379}
  autoconfigure:
    exclude:
      - org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration
      - org.springframework.boot.autoconfigure.data.redis.RedisReactiveAutoConfiguration
```

```yaml
app:
  security:
    password-pepper: ${PASSWORD_PEPPER}
    jwt:
      private-key: ${JWT_PRIVATE_KEY}
      public-key: ${JWT_PUBLIC_KEY}
    rate-limit:
      login:
        capacity: 10
        window-seconds: 60
```

(Only the `data`/`autoconfigure` keys under `spring:` and the `rate-limit` key under `app.security:` are new — the rest of the file is unchanged, shown for context.)

- [ ] **Step 6: Confirm the full existing test suite still passes with the new config/dependencies alone (no new code yet)**

Run: `./mvnw test`
Expected: `BUILD SUCCESS`, all existing tests green (this is the checkpoint proving the `RedisAutoConfiguration` exclusion works — no test yet touches Redis at all, so this only proves the exclusion didn't break anything by itself)

- [ ] **Step 7: Commit**

```bash
git add docker-compose.yml pom.xml src/main/resources/application.yml
git commit -m "chore(auth-6): add Redis infra and Bucket4j dependencies for login rate limiting"
```

---

### Task 2: `ClientIpResolver`

**Files:**
- Create: `src/main/java/br/com/fiap/hackaton/auth/ratelimit/ClientIpResolver.java`
- Test: `src/test/java/br/com/fiap/hackaton/auth/ratelimit/ClientIpResolverTest.java`

**Interfaces:**
- Produces: `static String ClientIpResolver.resolve(HttpServletRequest request)` — used by `LoginRateLimitFilter` in Task 4.

- [ ] **Step 1: Write the failing test**

Create `src/test/java/br/com/fiap/hackaton/auth/ratelimit/ClientIpResolverTest.java`:

```java
package br.com.fiap.hackaton.auth.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class ClientIpResolverTest {

  @Test
  void usesFirstIpFromForwardedForHeaderWhenPresent() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("X-Forwarded-For", "203.0.113.5, 10.0.0.2");

    assertThat(ClientIpResolver.resolve(request)).isEqualTo("203.0.113.5");
  }

  @Test
  void trimsWhitespaceAroundForwardedForIp() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("X-Forwarded-For", "  203.0.113.5  ,10.0.0.2");

    assertThat(ClientIpResolver.resolve(request)).isEqualTo("203.0.113.5");
  }

  @Test
  void fallsBackToRemoteAddrWhenHeaderAbsent() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRemoteAddr("192.168.1.10");

    assertThat(ClientIpResolver.resolve(request)).isEqualTo("192.168.1.10");
  }

  @Test
  void fallsBackToRemoteAddrWhenHeaderBlank() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("X-Forwarded-For", "   ");
    request.setRemoteAddr("192.168.1.10");

    assertThat(ClientIpResolver.resolve(request)).isEqualTo("192.168.1.10");
  }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./mvnw test -Dtest=ClientIpResolverTest`
Expected: FAIL to compile — `ClientIpResolver` does not exist yet

- [ ] **Step 3: Write the implementation**

Create `src/main/java/br/com/fiap/hackaton/auth/ratelimit/ClientIpResolver.java`:

```java
package br.com.fiap.hackaton.auth.ratelimit;

import jakarta.servlet.http.HttpServletRequest;

final class ClientIpResolver {

  private static final String FORWARDED_FOR_HEADER = "X-Forwarded-For";

  private ClientIpResolver() {}

  static String resolve(HttpServletRequest request) {
    String forwardedFor = request.getHeader(FORWARDED_FOR_HEADER);
    if (forwardedFor != null && !forwardedFor.isBlank()) {
      return forwardedFor.split(",")[0].trim();
    }
    return request.getRemoteAddr();
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./mvnw test -Dtest=ClientIpResolverTest`
Expected: `Tests run: 4, Failures: 0, Errors: 0`

- [ ] **Step 5: Commit**

```bash
git add src/main/java/br/com/fiap/hackaton/auth/ratelimit/ClientIpResolver.java src/test/java/br/com/fiap/hackaton/auth/ratelimit/ClientIpResolverTest.java
git commit -m "feat(auth-6): add ClientIpResolver for X-Forwarded-For-aware IP extraction"
```

---

### Task 3: `LazyLoginRateLimitProxyManager`

**Files:**
- Create: `src/main/java/br/com/fiap/hackaton/auth/ratelimit/LazyLoginRateLimitProxyManager.java`
- Test: `src/test/java/br/com/fiap/hackaton/auth/ratelimit/LazyLoginRateLimitProxyManagerTest.java`

**Interfaces:**
- Consumes: `io.lettuce.core.RedisClient` (constructed by `RateLimitConfig` in Task 5, or directly by tests).
- Produces: `ProxyManager<String> get()` — lazily connects and caches; used by `LoginRateLimitFilter` in Task 4 via a `Supplier<ProxyManager<String>>` (`this::get`).

- [ ] **Step 1: Write the failing test**

Create `src/test/java/br/com/fiap/hackaton/auth/ratelimit/LazyLoginRateLimitProxyManagerTest.java`:

```java
package br.com.fiap.hackaton.auth.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import java.time.Duration;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

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
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./mvnw test -Dtest=LazyLoginRateLimitProxyManagerTest`
Expected: FAIL to compile — `LazyLoginRateLimitProxyManager` does not exist yet

- [ ] **Step 3: Write the implementation**

Create `src/main/java/br/com/fiap/hackaton/auth/ratelimit/LazyLoginRateLimitProxyManager.java`:

```java
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./mvnw test -Dtest=LazyLoginRateLimitProxyManagerTest`
Expected: `Tests run: 2, Failures: 0, Errors: 0`

- [ ] **Step 5: Commit**

```bash
git add src/main/java/br/com/fiap/hackaton/auth/ratelimit/LazyLoginRateLimitProxyManager.java src/test/java/br/com/fiap/hackaton/auth/ratelimit/LazyLoginRateLimitProxyManagerTest.java
git commit -m "feat(auth-6): add lazily-connected Redis-backed Bucket4j ProxyManager"
```

---

### Task 4: `LoginRateLimitFilter`

**Files:**
- Create: `src/main/java/br/com/fiap/hackaton/auth/ratelimit/LoginRateLimitFilter.java`
- Test: `src/test/java/br/com/fiap/hackaton/auth/ratelimit/LoginRateLimitFilterTest.java`

**Interfaces:**
- Consumes: `Supplier<ProxyManager<String>>` (Task 3's `LazyLoginRateLimitProxyManager::get`, wired in Task 5), `com.fasterxml.jackson.databind.ObjectMapper`, `int capacity`, `int windowSeconds`; `ClientIpResolver.resolve(HttpServletRequest)` (Task 2); `br.com.fiap.hackaton.auth.web.ErrorResponse` (existing).
- Produces: `public LoginRateLimitFilter(Supplier<ProxyManager<String>>, ObjectMapper, int, int)` — used by `RateLimitConfig` in Task 5.

- [ ] **Step 1: Write the failing test**

Create `src/test/java/br/com/fiap/hackaton/auth/ratelimit/LoginRateLimitFilterTest.java`:

```java
package br.com.fiap.hackaton.auth.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.distributed.BucketProxy;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import jakarta.servlet.FilterChain;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class LoginRateLimitFilterTest {

  private final ObjectMapper objectMapper = new ObjectMapper();

  @Test
  void allowsRequestAndContinuesChainWhenUnderLimit() throws Exception {
    BucketProxy bucket = mock(BucketProxy.class);
    when(bucket.tryConsumeAndReturnRemaining(1)).thenReturn(ConsumptionProbe.consumed(9, 0));
    ProxyManager<String> proxyManager = proxyManagerReturning(bucket);
    LoginRateLimitFilter filter =
        new LoginRateLimitFilter(() -> proxyManager, objectMapper, 10, 60);
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilterInternal(request, response, chain);

    verify(chain).doFilter(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
  }

  @Test
  void rejectsWithTooManyRequestsAndRetryAfterWhenOverLimit() throws Exception {
    BucketProxy bucket = mock(BucketProxy.class);
    when(bucket.tryConsumeAndReturnRemaining(1))
        .thenReturn(
            ConsumptionProbe.rejected(
                0, TimeUnit.SECONDS.toNanos(30), TimeUnit.SECONDS.toNanos(30)));
    ProxyManager<String> proxyManager = proxyManagerReturning(bucket);
    LoginRateLimitFilter filter =
        new LoginRateLimitFilter(() -> proxyManager, objectMapper, 10, 60);
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilterInternal(request, response, chain);

    verifyNoInteractions(chain);
    assertThat(response.getStatus()).isEqualTo(429);
    assertThat(response.getHeader("Retry-After")).isEqualTo("30");
    assertThat(response.getContentAsString()).contains("Too many login attempts");
  }

  @Test
  void allowsRequestWhenProxyManagerSupplierThrows() throws Exception {
    LoginRateLimitFilter filter =
        new LoginRateLimitFilter(
            () -> {
              throw new IllegalStateException("redis unavailable");
            },
            objectMapper,
            10,
            60);
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilterInternal(request, response, chain);

    verify(chain).doFilter(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
  }

  @SuppressWarnings("unchecked")
  private ProxyManager<String> proxyManagerReturning(BucketProxy bucket) {
    ProxyManager<String> proxyManager = mock(ProxyManager.class);
    when(proxyManager.getProxy(anyString(), any())).thenReturn(bucket);
    return proxyManager;
  }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./mvnw test -Dtest=LoginRateLimitFilterTest`
Expected: FAIL to compile — `LoginRateLimitFilter` does not exist yet

- [ ] **Step 3: Write the implementation**

Create `src/main/java/br/com/fiap/hackaton/auth/ratelimit/LoginRateLimitFilter.java`:

```java
package br.com.fiap.hackaton.auth.ratelimit;

import br.com.fiap.hackaton.auth.web.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

public class LoginRateLimitFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(LoginRateLimitFilter.class);
  private static final String KEY_PREFIX = "login-rate-limit:";

  private final Supplier<ProxyManager<String>> proxyManagerSupplier;
  private final ObjectMapper objectMapper;
  private final int capacity;
  private final int windowSeconds;

  public LoginRateLimitFilter(
      Supplier<ProxyManager<String>> proxyManagerSupplier,
      ObjectMapper objectMapper,
      int capacity,
      int windowSeconds) {
    this.proxyManagerSupplier = proxyManagerSupplier;
    this.objectMapper = objectMapper;
    this.capacity = capacity;
    this.windowSeconds = windowSeconds;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    RateLimitDecision decision = decide(request);

    if (decision.allowed()) {
      filterChain.doFilter(request, response);
      return;
    }

    response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    response.setHeader(HttpHeaders.RETRY_AFTER, String.valueOf(decision.retryAfterSeconds()));
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response
        .getWriter()
        .write(
            objectMapper.writeValueAsString(
                new ErrorResponse("Too many login attempts. Try again later.")));
  }

  private RateLimitDecision decide(HttpServletRequest request) {
    try {
      ProxyManager<String> proxyManager = proxyManagerSupplier.get();
      String key = KEY_PREFIX + ClientIpResolver.resolve(request);
      Supplier<BucketConfiguration> configuration =
          () ->
              BucketConfiguration.builder()
                  .addLimit(Bandwidth.simple(capacity, Duration.ofSeconds(windowSeconds)))
                  .build();
      Bucket bucket = proxyManager.getProxy(key, configuration);
      ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

      if (probe.isConsumed()) {
        return RateLimitDecision.allowed();
      }
      long retryAfterSeconds =
          Math.max(1, TimeUnit.NANOSECONDS.toSeconds(probe.getNanosToWaitForRefill()));
      return RateLimitDecision.rejected(retryAfterSeconds);
    } catch (RuntimeException ex) {
      log.warn("Login rate limiter unavailable, allowing request without rate limiting", ex);
      return RateLimitDecision.allowed();
    }
  }

  private record RateLimitDecision(boolean allowed, long retryAfterSeconds) {
    static RateLimitDecision allowed() {
      return new RateLimitDecision(true, 0);
    }

    static RateLimitDecision rejected(long retryAfterSeconds) {
      return new RateLimitDecision(false, retryAfterSeconds);
    }
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./mvnw test -Dtest=LoginRateLimitFilterTest`
Expected: `Tests run: 3, Failures: 0, Errors: 0`

- [ ] **Step 5: Commit**

```bash
git add src/main/java/br/com/fiap/hackaton/auth/ratelimit/LoginRateLimitFilter.java src/test/java/br/com/fiap/hackaton/auth/ratelimit/LoginRateLimitFilterTest.java
git commit -m "feat(auth-6): add LoginRateLimitFilter with fail-open behavior"
```

---

### Task 5: Wire `RateLimitConfig`

**Files:**
- Create: `src/main/java/br/com/fiap/hackaton/auth/ratelimit/RateLimitConfig.java`

**Interfaces:**
- Consumes: `RedisProperties` (Spring Boot autoconfigure class, registered by hand here since `RedisAutoConfiguration` is excluded), `LazyLoginRateLimitProxyManager` (Task 3), `LoginRateLimitFilter` (Task 4), `ObjectMapper` (Spring Boot default bean), `@Value` reads of `app.security.rate-limit.login.capacity`/`window-seconds` (Task 1's `application.yml`).
- Produces: a registered `FilterRegistrationBean<LoginRateLimitFilter>` active on `/auth/login` in the full application context — no new public interface consumed by later tasks, this is the wiring endpoint. Task 6 tests against the running filter chain, not against this class directly.

No new test file for this task — `RateLimitConfig` is pure wiring with no branching logic of its own; it's proven correct by Task 6's end-to-end test actually exercising the filter through a real `MockMvc` request.

- [ ] **Step 1: Write `RateLimitConfig`**

Create `src/main/java/br/com/fiap/hackaton/auth/ratelimit/RateLimitConfig.java`:

```java
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
```

- [ ] **Step 2: Confirm the full existing test suite still passes**

Run: `./mvnw test`
Expected: `BUILD SUCCESS` — this is the checkpoint proving that adding the filter registration to the full application context does not break any existing `@SpringBootTest`, including `AuthControllerLoginTest`, which now genuinely routes through `LoginRateLimitFilter` on every `POST /auth/login` call and must still pass via the fail-open path (no Redis container declared in that test)

- [ ] **Step 3: Commit**

```bash
git add src/main/java/br/com/fiap/hackaton/auth/ratelimit/RateLimitConfig.java
git commit -m "feat(auth-6): wire LoginRateLimitFilter into the application context"
```

---

### Task 6: End-to-end integration tests

**Files:**
- Create: `src/test/java/br/com/fiap/hackaton/auth/ratelimit/LoginRateLimitIntegrationTest.java`

**Interfaces:**
- Consumes: the full Spring application context (via `@SpringBootTest` + `@AutoConfigureMockMvc`), a real Redis `GenericContainer`, `@DynamicPropertySource` (per the spec's testing-strategy note: `@ServiceConnection` doesn't apply here since `RedisAutoConfiguration` is excluded and this config reads `RedisProperties` directly, not `RedisConnectionDetails`).
- Produces: the acceptance-criteria proof — nothing later depends on this file.

- [ ] **Step 1: Write the integration test**

Create `src/test/java/br/com/fiap/hackaton/auth/ratelimit/LoginRateLimitIntegrationTest.java`:

```java
package br.com.fiap.hackaton.auth.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

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

@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(
    properties = {
      "app.security.rate-limit.login.capacity=3",
      "app.security.rate-limit.login.window-seconds=60"
    })
class LoginRateLimitIntegrationTest {

  @Container
  @ServiceConnection
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
          () -> BucketConfiguration.builder().addLimit(Bandwidth.simple(1, Duration.ofMinutes(1))).build();
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
```

- [ ] **Step 2: Run the tests to verify they fail (class doesn't exist yet, or fails before implementation quirks are ironed out)**

Run: `./mvnw test -Dtest=LoginRateLimitIntegrationTest`
Expected: since Tasks 1-5 are already implemented at this point, this should mostly work on the first try — but run it now to confirm before declaring done. If `sharesTheCounterAcrossTwoIndependentReplicaConnections` fails because a bucket key from a previous test run collides, the `System.nanoTime()`-suffixed key already prevents that; investigate any other failure per superpowers:systematic-debugging rather than adjusting assertions to fit unexpected output.

- [ ] **Step 3: Run the tests to verify they pass**

Run: `./mvnw test -Dtest=LoginRateLimitIntegrationTest`
Expected: `Tests run: 3, Failures: 0, Errors: 0`

- [ ] **Step 4: Run the complete test suite one final time**

Run: `./mvnw test`
Expected: `BUILD SUCCESS` — every pre-existing test (Postgres-only, no Redis container) still passes via the fail-open path, and the new rate-limit tests pass with a real Redis container. This is the final regression check for the whole card.

- [ ] **Step 5: Run the full verify build (Spotless + JaCoCo included)**

Run: `./mvnw verify`
Expected: `BUILD SUCCESS`. If Spotless fails formatting, run `./mvnw spotless:apply` and re-run `./mvnw verify`.

- [ ] **Step 6: Commit**

```bash
git add src/test/java/br/com/fiap/hackaton/auth/ratelimit/LoginRateLimitIntegrationTest.java
git commit -m "test(auth-6): add end-to-end proof of login rate limiting across replicas"
```

---

## After this plan

Per the spec's "Out of scope" section: no other endpoint is rate-limited, no per-user limiting, no Redis auth/TLS. If a future card needs rate limiting elsewhere, extract a generic version of `LoginRateLimitFilter`/`RateLimitConfig` at that point — not before (YAGNI, confirmed with the user during brainstorming).
