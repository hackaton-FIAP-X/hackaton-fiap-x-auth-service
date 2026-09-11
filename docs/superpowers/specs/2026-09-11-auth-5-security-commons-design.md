# AUTH-5: security-commons — Resource Server autoconfiguration

## Context

ClickUp card `[AUTH-5] Modulo compartilhado security-commons`:

> Objetivo: Autoconfiguracao de Resource Server empacotada como dependencia
> reutilizavel.
>
> Criterios de aceite:
> - O video-service ganha autenticacao adicionando uma dependencia e uma
>   property
> - Nenhum codigo de seguranca copiado entre servicos
> - Extrai o userId do claim sub e disponibiliza para os controllers
>
> Impacto: Desbloqueia a VID-2.

`VID-2` is already complete: the video-service team did not wait and hand-rolled
their own Resource Server config against a fixture JWKS, per their card's own
instruction ("Enquanto AUTH-4 e AUTH-5 nao ficam prontas, teste com uma JWKS
estatica de fixture. Nao espere o colega."). So `security-commons` no longer
unblocks anything time-critical — its value now is eliminating duplicated
security code across services (video-service today, `processing-worker`
later), and giving video-service a real JWKS to point at (AUTH-4, already
shipped) instead of its fixture.

`F-1` originally planned a monorepo (`services/*`, `shared/security-commons`).
That plan was abandoned — `auth-service` and `video-service` are separate
GitHub repos today, each with its own `pom.xml`, Spring Boot 3.3.4, Java 21.

### What video-service already built (read from
`github.com/hackaton-FIAP-X/hackaton-fiap-x-video-service`, shallow-cloned
read-only for this analysis)

- `JwtProperties` (`@ConfigurationProperties(prefix = "security.jwt")`):
  `jwksUri`, `issuer`.
- `SecurityConfig`: stateless `SecurityFilterChain`, a public-endpoint
  allowlist (actuator health/info/prometheus, swagger/api-docs), OAuth2
  Resource Server with a `NimbusJwtDecoder.withJwkSetUri(...)` decoder and a
  validator chain (`JwtValidators.createDefault[WithIssuer]` +
  `SubjectIsUuidValidator`).
- `SubjectIsUuidValidator`: rejects tokens whose `sub` claim isn't a parseable
  `UUID`.
- `ProblemDetailSecurityResponder`: `AuthenticationEntryPoint` +
  `AccessDeniedHandler` returning RFC 7807 `ProblemDetail` (401/403) instead
  of Spring Security's default response.
- `CurrentUserId` + `CurrentUserIdArgumentResolver` (+ `WebMvcConfigurer`
  registration): lets a controller declare `@CurrentUserId UUID userId` and
  get `UUID.fromString(jwt.getSubject())`, sourced from
  `SecurityContextHolder`.

This is precisely the code `security-commons` needs to absorb and generalize
(video-service's `sub` is a `UUID`, matching `auth-service`'s own
`User.id : UUID` — see `JwtTokenService.generateToken`, which sets
`.subject(user.getId().toString())`).

## Decisions already confirmed with the user

1. **Distribution:** publish to **GitHub Packages** (Maven registry) via a new
   GitHub Actions workflow in this repo — not just local `mvn install`.
2. **Repo structure:** `security-commons/` as a **standalone Maven project**
   in a subdirectory of `hackaton-fiap-x-auth-service`, **not** a reactor
   module of the root `pom.xml`. The existing `auth-service` root
   `pom.xml`/`Dockerfile`/`docker-compose.yml` are untouched.
3. **Scope:** this card covers `security-commons` itself — build, tests,
   publish pipeline — living in `hackaton-fiap-x-auth-service`. Migrating
   `video-service` to actually depend on it is explicitly **out of scope**
   here (VID-2 is closed and shipped); that migration is a follow-up in the
   video-service repo, not touched by this work.

## Approach

**Spring Boot autoconfiguration** (`@AutoConfiguration`, activated via
`META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`),
not a library of classes a consumer has to `@Import` manually. This is what
lets a consumer satisfy the acceptance criterion literally: add the Maven
dependency + set `security.jwt.jwks-uri`, get a working Resource Server, no
`@Import`/component-scan changes.

Every bean is `@ConditionalOnMissingBean`, so a consuming service can override
any single piece (e.g. supply its own `AuthenticationEntryPoint`) without
forking the module.

## Module layout

```
security-commons/
  pom.xml                         (standalone Maven project, not a reactor module)
  src/main/java/br/com/fiap/hackaton/security/commons/
    SecurityCommonsProperties.java
    ResourceServerAutoConfiguration.java
    SubjectIsUuidValidator.java
    ProblemDetailAuthEntryPoint.java
    CurrentUserId.java
    CurrentUserIdArgumentResolver.java
    WebMvcAutoConfiguration.java
  src/main/resources/META-INF/spring/
    org.springframework.boot.autoconfigure.AutoConfiguration.imports
  src/test/java/...
```

Coordinates: `groupId br.com.fiap.hackaton.security`,
`artifactId security-commons`. Package base
`br.com.fiap.hackaton.security.commons` — deliberately generic (no `auth` or
`video` in the name), since a third service will consume this too.

## Configuration surface

Reuses the exact property prefix video-service already has in production, so
a future migration is a dependency swap, not a YAML rewrite:

```yaml
security:
  jwt:
    jwks-uri: https://.../.​well-known/jwks.json   # required — activates the autoconfiguration
    issuer: fiapx-auth                              # optional
    public-endpoints:                                # optional, sensible default below
      - /actuator/health
      - /actuator/health/**
      - /actuator/info
      - /actuator/prometheus
      - /api-docs
      - /api-docs/**
      - /swagger-ui.html
      - /swagger-ui/**
```

`ResourceServerAutoConfiguration` is gated by
`@ConditionalOnProperty(prefix = "security.jwt", name = "jwks-uri")` — no
`jwks-uri`, no security filter chain gets registered, so the module is inert
until configured (important for `auth-service`'s own test contexts, which
don't set this property).

## Components

- **`SecurityCommonsProperties`** — record-based `@ConfigurationProperties`,
  holds `jwksUri`, `issuer` (nullable), `publicEndpoints` (`List<String>`,
  defaulted in the record's compact constructor rather than via `@Value`, so
  it also works if a consumer partially overrides the property).
- **`ResourceServerAutoConfiguration`** — `@AutoConfiguration`,
  `@ConditionalOnClass({SecurityFilterChain.class, JwtDecoder.class})`,
  `@ConditionalOnProperty(...)` as above, `@EnableConfigurationProperties`.
  Provides:
  - `@Bean @ConditionalOnMissingBean JwtDecoder` — Nimbus decoder over
    `jwksUri`, validator chain = `JwtValidators.createDefault[WithIssuer]` +
    `SubjectIsUuidValidator`.
  - `@Bean @ConditionalOnMissingBean SecurityFilterChain` — stateless,
    `publicEndpoints` permitted, `OPTIONS /**` permitted, everything else
    `authenticated()`, wired to the Resource Server JWT converter and to
    `ProblemDetailAuthEntryPoint` for both the entry point and the access-denied
    handler.
- **`SubjectIsUuidValidator`** — ported as-is (generic already, no
  service-specific naming in the original).
- **`ProblemDetailAuthEntryPoint`** — same shape as video-service's
  `ProblemDetailSecurityResponder`, but the RFC 7807 `type` URIs are generic
  constants owned by this module (`urn:problem-type:unauthorized` /
  `urn:problem-type:forbidden`) instead of reaching into a service's own
  `ProblemTypes` class. `@Bean @ConditionalOnMissingBean` so a service that
  wants its own problem-type taxonomy can still override it.
- **`CurrentUserId`** — marker annotation, `@Target(PARAMETER)`.
- **`CurrentUserIdArgumentResolver`** — identical semantics to
  video-service's: reads `Jwt` off `SecurityContextHolder`, requires it be
  present and `UUID`-shaped (guaranteed at this point by
  `SubjectIsUuidValidator` already having rejected anything else at the
  filter chain), throws `ResponseStatusException(401)` if the parameter is
  used somewhere unauthenticated slips through.
- **`WebMvcAutoConfiguration`** — separate `@AutoConfiguration`,
  `@ConditionalOnClass(WebMvcConfigurer.class)`, registers the argument
  resolver. Split from `ResourceServerAutoConfiguration` because the argument
  resolver is useful even in contexts that assemble the filter chain
  differently — keeps the two concerns independently overridable.

## Data flow

1. Request hits a consuming service with `Authorization: Bearer <token>`.
2. Spring Security's Resource Server filter asks the `JwtDecoder` (Nimbus) to
   validate the signature against the JWKS at `jwks-uri` (cached per Nimbus's
   own JWK set cache) and run the validator chain (expiry, issuer if
   configured, `sub` is a UUID).
3. On success, `Jwt` becomes the `Authentication` principal;
   `CurrentUserIdArgumentResolver` reads `sub` off it for any controller
   parameter annotated `@CurrentUserId UUID`.
4. On failure (missing/expired/invalid/wrong issuer/non-UUID `sub`),
   `ProblemDetailAuthEntryPoint` writes a 401 `ProblemDetail`; on an
   authenticated-but-forbidden path (future authorization rules), it writes a
   403 in the same shape.

## Testing strategy

No Testcontainers/Docker anywhere in this module — deliberate, given the
Docker/`docker-java` incompatibility hit during AUTH-4 on this machine.
Autoconfiguration is naturally testable without a container:

- **`ApplicationContextRunner`** tests (from `spring-boot-test`) for the
  conditional-activation matrix: no `jwks-uri` → no filter chain bean; with
  `jwks-uri` → beans present; a user-supplied `JwtDecoder`/`SecurityFilterChain`
  bean → autoconfiguration backs off.
- **One lightweight `@SpringBootTest`** using a minimal test-only
  `@SpringBootApplication` fixture (`src/test/java`, not shipped in the
  artifact) plus a local JWKS stub (an embedded `com.sun.net.httpserver` or a
  small WireMock instance — no external process, no Docker) to prove the real
  flow end-to-end: a token signed with a locally generated RSA test keypair,
  submitted to a protected test controller — asserts 401 with no token, 200
  plus the correct `UUID` `userId` with a valid token, 401 with a token whose
  `sub` isn't a UUID.

## Publishing

- `security-commons/pom.xml` gets a `<distributionManagement>` pointing at
  this repo's GitHub Packages Maven registry
  (`https://maven.pkg.github.com/hackaton-FIAP-X/hackaton-fiap-x-auth-service`).
- New `.github/workflows/publish-security-commons.yml` (first CI workflow in
  this repo — none exists today): triggers on push to `main` touching
  `security-commons/**`, runs `mvn -f security-commons/pom.xml -B deploy`
  authenticated with the built-in `GITHUB_TOKEN`.
- Consumers add the same GitHub Packages `<repository>` plus the
  `security-commons` dependency and the `security.jwt.jwks-uri` property —
  the literal shape of the acceptance criterion.

## Out of scope (explicitly, per user decision)

- Touching the `video-service` repository or migrating `VID-2`'s
  hand-rolled security code to this module.
- Converting `hackaton-fiap-x-auth-service` into a Maven reactor / multi-module
  layout.
- `auth-service` itself adopting `security-commons` for its own (currently
  nonexistent) protected endpoints — not needed yet, no such endpoints exist.

## Open risk

GitHub Packages requires authentication even to **read** public packages from
another repo in some configurations (org policy dependent) — video-service's
eventual migration will need a `~/.m2/settings.xml` (or CI secret) with a
`read:packages` token. Not this card's problem to solve, but worth flagging
in the follow-up ticket so it isn't a surprise.
