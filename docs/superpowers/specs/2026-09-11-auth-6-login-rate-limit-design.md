# AUTH-6: Rate limit on login with Bucket4j and Redis

## Context

ClickUp card `[AUTH-6] Rate limit no login com Bucket4j e Redis`:

> Objetivo: Proteger o login contra forca bruta e absorver pico na borda.
>
> Criterios de aceite:
> - Limite configuravel, sugestao de 10 tentativas por minuto por IP
> - Excedente retorna 429 com header Retry-After
> - Contador compartilhado no Redis, funcionando com mais de uma replica
>
> Valor na apresentacao: Argumento direto para o requisito de resistencia a
> pico.

`main` already has `POST /auth/login` (AUTH-3, `AuthController` /
`AuthenticationService` / `JwtTokenService`) and the `security-commons`
module (AUTH-5). Neither Redis nor any rate-limiting dependency exists yet in
`pom.xml` or `docker-compose.yml`.

## Decisions confirmed with the user

1. **Scope:** login-only. No generic reusable rate-limit mechanism is built
   now — YAGNI. If a second endpoint needs this later, extract then.
2. **Client IP extraction:** first IP in `X-Forwarded-For` if present,
   otherwise `HttpServletRequest.getRemoteAddr()`. Accepted risk: without a
   trusted reverse proxy in front, the header is spoofable — acceptable for
   this deployment (behind an ingress/load balancer in the target
   environment).
3. **What counts against the limit:** every request that reaches
   `POST /auth/login`, regardless of the authentication outcome. This is
   simpler (no coupling to `AuthenticationService`'s result) and matches the
   card's "absorver pico na borda" framing — the point is edge protection,
   not just brute-force accounting.
4. **Redis client:** `spring-boot-starter-data-redis` (Lettuce, Spring
   Boot's default) + `bucket4j-redis`'s Lettuce integration. This reuses
   Spring Boot's own `RedisConnectionFactory` autoconfiguration
   (`spring.data.redis.host` / `port`) instead of hand-rolling a Jedis pool
   or pulling in Redisson (evaluated and rejected — Redisson's distributed
   objects/locks are unneeded weight for a single counter).
5. **Redis unavailable:** fail-open. A connectivity failure while
   consuming/creating the bucket is caught, logged at `WARN`, and the request
   is allowed through unrated. Login availability is the higher priority;
   losing rate-limiting during a transient Redis outage is an acceptable
   trade-off.

## Approach

A `jakarta.servlet.Filter`, registered only for `/auth/login` via a
`FilterRegistrationBean`, runs before the `DispatcherServlet`:

1. Extract the client IP (per decision 2).
2. Ask Bucket4j for a bucket keyed `"login-rate-limit:" + ip`, backed by a
   distributed `ProxyManager` over the shared Lettuce connection — the same
   key resolves to the same counter regardless of which `auth-service`
   replica handles the request, which is what makes this work across
   multiple instances.
3. Try to consume 1 token.
   - Allowed → `filterChain.doFilter(request, response)`, request proceeds
     normally.
   - Rejected → write `429` directly on the `HttpServletResponse`, with a
     `Retry-After` header (seconds, derived from Bucket4j's
     `nanosToWaitForRefill`) and a JSON body reusing the existing
     `ErrorResponse` record.
   - Redis/connectivity error at any point above → log `WARN`, treat as
     allowed (fail-open, per decision 5).

A filter is chosen over a `HandlerInterceptor` because it runs ahead of
Spring MVC's handler mapping — closer to "the borda" the card asks for, and
it does not depend on `DispatcherServlet` internals.

## Configuration

New `app.security.rate-limit.login` section, `@ConfigurationProperties`,
defaults matching the acceptance criterion so the feature works out of the
box with no YAML changes required:

```yaml
app:
  security:
    rate-limit:
      login:
        capacity: 10        # max attempts per window
        window-seconds: 60  # refill window
```

Plus the Redis connection itself, under Spring Boot's own top-level prefix
(not nested under `app.security`):

```yaml
spring:
  data:
    redis:
      host: ${REDIS_HOST:localhost}
      port: ${REDIS_PORT:6379}
  autoconfigure:
    exclude:
      - org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration
      - org.springframework.boot.autoconfigure.data.redis.RedisReactiveAutoConfiguration
```

(see the regression-risk note below for why the exclusions are required)

`capacity` and `window-seconds` are read as plain `int`s (no need for a
`Duration`/`DataSize` type here — a single scalar window in seconds is
simplest and matches "10 tentativas por minuto" literally when
`window-seconds: 60`).

## Regression risk with existing tests (discovered during technical research)

`spring-boot-starter-data-redis` on the classpath makes Spring Boot
autoconfigure its own `LettuceConnectionFactory`/`RedisConnectionFactory`
bean (`RedisAutoConfiguration`), which by default attempts an eager
connection during `ApplicationContext` startup. Every existing
`@SpringBootTest` in this repo (`AuthControllerLoginTest`,
`JwtTokenServiceTest`, `FlywayMigrationTest`, etc.) declares only a
Postgres Testcontainer, not Redis — an eager Redis connection attempt at
context refresh would fail all of them.

Mitigation: exclude `RedisAutoConfiguration` (and, for safety,
`RedisReactiveAutoConfiguration`) via
`spring.autoconfigure.exclude` in `application.yml`, and register
`RedisProperties` ourselves with `@EnableConfigurationProperties` on our
own `RateLimitConfig` — we only need `RedisProperties` for `host`/`port`,
never Spring Data Redis's own connection factory. Combined with the lazy,
per-request-guarded connection described in Components below, no Redis
connection is ever attempted outside a real request to `/auth/login`, so
none of the existing tests need to change.

## Components

- **`RateLimitConfig`** — `@Configuration`, `@EnableConfigurationProperties(RedisProperties.class)`
  (see regression-risk note above for why this is registered by hand).
  Produces: the `RedisClient` bean (from `RedisProperties.host`/`port`,
  `destroyMethod = "shutdown"`), and the `FilterRegistrationBean` wiring
  `LoginRateLimitFilter` to `urlPatterns = ["/auth/login"]`. `capacity` and
  `windowSeconds` are read via plain `@Value("${app.security.rate-limit.login.capacity:10}")`
  /`@Value("${app.security.rate-limit.login.window-seconds:60}")` on the
  `@Bean` factory method — matching how this app's *own* config classes
  (`JwtKeyConfig`, `PasswordEncoderConfig`) already read scalar properties,
  rather than introducing a `@ConfigurationProperties` record (that pattern
  is what `security-commons` uses because it's a standalone autoconfiguration
  library; this is the main app, which uses `@Value` everywhere today).
- **`LoginRateLimitFilter`** (extends `OncePerRequestFilter`) — the filter
  described in Approach. Takes a `Supplier<ProxyManager<String>>` (not a
  `ProxyManager` directly) plus `capacity`/`windowSeconds`, constructor
  -injected — no dependency on `AuthenticationService`, so it can be
  unit-tested with a fake supplier (returning a mock, or throwing to
  simulate Redis being down) without any Spring context or real Lettuce
  client.
- **`LazyLoginRateLimitProxyManager`** — wraps a `RedisClient` (creating one
  does not open a network connection — only `.connect(...)` does) and lazily
  builds+caches the Lettuce-backed `ProxyManager<String>` on first use,
  double-checked-locked. Connection failures surface as an unchecked
  exception on that first call, which `LoginRateLimitFilter`'s per-request
  try/catch turns into fail-open — this is what makes fail-open true both
  for "Redis was up, now it's down" and "Redis was never reachable in the
  first place" (e.g. it not being started yet, or a test context with no
  Redis at all).
- **`ClientIpResolver`** — small static helper (or package-private method on
  the filter, decided during implementation) implementing decision 2. Kept
  separate enough to unit-test the `X-Forwarded-For` / fallback logic in
  isolation.

Reuses the existing `br.com.fiap.hackaton.auth.web.ErrorResponse` record for
the 429 body — no new error DTO.

## Data flow

1. Request hits `POST /auth/login`.
2. `LoginRateLimitFilter` resolves the client IP and asks the
   `ProxyManager`-backed bucket for `"login-rate-limit:" + ip` to try-consume
   1 token.
3. Redis holds the actual counter state (via Bucket4j's Redis
   integration), so every `auth-service` replica consulting the same Redis
   sees the same remaining count for that IP.
4. Within limit → request reaches `AuthController.login` unchanged.
5. Over limit → filter short-circuits with `429` + `Retry-After`, controller
   is never invoked, `AuthenticationService` never runs.
6. Redis unreachable → filter logs and short-circuits to "allowed", request
   reaches the controller as if no rate limiting existed.

## Infrastructure changes

- `docker-compose.yml`: new `redis:7-alpine` service (`redis`), exposing
  `6379`, with a healthcheck (`redis-cli ping`); `auth-service` gets
  `REDIS_HOST=redis` / `REDIS_PORT=6379` and a `depends_on: redis:
  condition: service_healthy`, mirroring the existing `postgres` service
  pattern.
- `pom.xml`: add `spring-boot-starter-data-redis` (for `RedisProperties`
  only, per the exclusions above), `com.bucket4j:bucket4j_jdk17-core` and
  `com.bucket4j:bucket4j_jdk17-lettuce` (both `8.14.0` — this repo targets
  Java 21, so the `_jdk17` artifact line, not the legacy unsuffixed
  `bucket4j-core`/`bucket4j-redis` coordinates from older Bucket4j
  releases), and an explicit `io.lettuce:lettuce-core` dependency with no
  version (bucket4j's Lettuce integration declares `lettuce-core` as
  `provided`, so the consumer must supply it — we let it resolve to
  whatever version Spring Boot 3.3.4's BOM manages, `6.3.2.RELEASE`, instead
  of pinning a second, possibly-mismatched version). `GenericContainer` for
  the Redis test container comes from `org.testcontainers:postgresql`'s
  existing transitive dependency on `org.testcontainers:testcontainers` —
  no new Testcontainers dependency needed.

## Testing strategy

Docker/Testcontainers works on this machine (verified before writing this
spec) — no reason to avoid it here the way `security-commons` did for AUTH-5.

Since `RedisAutoConfiguration` is excluded (regression-risk note above) and
we read `RedisProperties` directly rather than a `RedisConnectionDetails`
bean, Testcontainers' `@ServiceConnection` convenience (which populates
`RedisConnectionDetails`, not raw properties) has nothing to attach to for
Redis. Integration tests instead point our config at the container with a
plain `@DynamicPropertySource` setting `spring.data.redis.host`/`port` —
`@ServiceConnection` is kept for Postgres only, unaffected by this.

- **`ClientIpResolverTest`** (or filter-level unit test) — `X-Forwarded-For`
  present (single IP, multiple IPs — takes the first), absent (falls back to
  `getRemoteAddr()`).
- **`LoginRateLimitFilterTest`** — pure unit test with a mocked
  `ProxyManager`/`Bucket`: under limit → chain continues, untouched
  response; over limit → chain never invoked, response is 429 with
  `Retry-After` and the `ErrorResponse` JSON body; `ProxyManager` throwing →
  chain continues (fail-open), a WARN is logged.
- **`LoginRateLimitIntegrationTest`** — `@SpringBootTest` +
  `@Testcontainers` with a real Redis container: drives `capacity + 1`
  requests to `POST /auth/login` from the same IP, asserts the first
  `capacity` succeed (get past the filter — a 401 for bad credentials is a
  pass here, only the 429 matters) and the next is 429 with `Retry-After`.
  A second scenario opens a **second** `RedisConnectionFactory`/`ProxyManager`
  pointed at the same container to simulate a second replica, and asserts
  that a request against it is *already* rate-limited after the first
  "replica" exhausted the bucket — this is the concrete proof of "contador
  compartilhado no Redis, funcionando com mais de uma replica".
- Existing `AuthControllerLoginTest` / `AuthenticationServiceTest` are
  untouched — rate limiting sits in front of the controller, not inside it.

## Out of scope

- Rate limiting `POST /auth/register` or any other endpoint (decision 1).
- Distinguishing successful vs. failed login attempts for the counter
  (decision 3).
- Per-user (as opposed to per-IP) limiting.
- Redis persistence/eviction tuning, TLS, or auth — `docker-compose.yml`'s
  Redis is unauthenticated on the internal compose network, matching how
  Postgres is configured today in this same file for local/dev use.
