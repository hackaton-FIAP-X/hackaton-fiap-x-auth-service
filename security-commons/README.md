# security-commons

Spring Boot autoconfiguration for a JWKS-based OAuth2 Resource Server, shared
across FIAP-X services.

## Usage

1. Add the dependency:

```xml
<dependency>
    <groupId>br.com.fiap.hackaton.security</groupId>
    <artifactId>security-commons</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

(Also add the GitHub Packages `<repository>` pointing at
`https://maven.pkg.github.com/hackaton-FIAP-X/hackaton-fiap-x-auth-service`
to your `pom.xml` or `~/.m2/settings.xml`, authenticated with a
`read:packages` GitHub token. The published version is currently
`1.0.0-SNAPSHOT`, so the `<repository>` block also needs
`<snapshots><enabled>true</enabled></snapshots>` — without it Maven will
refuse to resolve a snapshot version from that repository.)

2. Set the JWKS URI:

```yaml
security:
  jwt:
    jwks-uri: https://auth-service.example/.well-known/jwks.json
```

That's it — every route is now authenticated except the default public
endpoints (`/actuator/health`, `/actuator/health/**`, `/actuator/info`,
`/actuator/prometheus`, `/api-docs`, `/api-docs/**`, `/swagger-ui.html`,
`/swagger-ui/**`; override with `security.jwt.public-endpoints` if you need a
different list). Optionally set `security.jwt.issuer` to also validate the
token's `iss` claim.

> **Note:** this module's autoconfiguration only activates the resource
> server once `security.jwt.jwks-uri` is set. If you add the dependency but
> never set that property, `spring-boot-starter-security` still arrives on
> the classpath transitively, so Spring Boot's own default security
> auto-configuration takes over instead — every endpoint gets protected by
> HTTP Basic auth with a randomly generated password logged at startup. This
> can be a confusing trap if the property is left unset by mistake.

3. Read the authenticated user's id in a controller:

```java
@GetMapping("/videos")
List<Video> list(@CurrentUserId UUID userId) {
    return videoService.findAllFor(userId);
}
```

`userId` comes straight from the token's `sub` claim, which this module
requires to be a valid UUID — never from the request body or query string.

## Overriding a default

Most beans (`ProblemDetailAuthEntryPoint`, `JwtDecoder`, `SecurityFilterChain`,
`CurrentUserIdArgumentResolver`, and others) are `@ConditionalOnMissingBean`:
declare your own bean of that type in your application and the
autoconfiguration backs off in favor of yours — e.g. for a custom error
responder, declare your own `ProblemDetailAuthEntryPoint` bean.

The one exception is the `WebMvcConfigurer` that registers the
`CurrentUserIdArgumentResolver` with Spring MVC
(`WebMvcAutoConfiguration#securityCommonsWebMvcConfigurer`) — that bean is
*not* conditional, since `WebMvcConfigurer` beans are additive by design in
Spring, not mutually exclusive. To customize the resolver's behavior, don't
try to override that configurer; instead supply your own
`CurrentUserIdArgumentResolver` bean (which *is* conditional), and the
configurer will register yours instead.
