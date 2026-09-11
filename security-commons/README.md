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
`read:packages` GitHub token.)

2. Set the JWKS URI:

```yaml
security:
  jwt:
    jwks-uri: https://auth-service.example/.well-known/jwks.json
```

That's it — every route is now authenticated except the default public
endpoints (`/actuator/health`, `/actuator/info`, `/actuator/prometheus`,
`/api-docs/**`, `/swagger-ui/**`; override with `security.jwt.public-endpoints`
if you need a different list). Optionally set `security.jwt.issuer` to also
validate the token's `iss` claim.

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

Every bean is `@ConditionalOnMissingBean`. To supply your own, e.g. a custom
error responder, just declare your own `ProblemDetailAuthEntryPoint` (or
`JwtDecoder`, or `SecurityFilterChain`) bean in your application — the
autoconfiguration backs off.
