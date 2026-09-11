# AUTH-5: security-commons Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a standalone, publishable `security-commons` Maven module that Spring Boot–autoconfigures an OAuth2 Resource Server (JWKS-based JWT validation) plus a `@CurrentUserId UUID` controller-argument resolver, so a consuming service only needs the dependency and a `security.jwt.jwks-uri` property.

**Architecture:** A `security-commons/` standalone Maven project (own `pom.xml`, not a reactor module of the root `auth-service` build) living inside this repo. Two `@AutoConfiguration` classes — one for the Resource Server (`JwtDecoder` + `SecurityFilterChain` + problem-detail error responses), one for the MVC argument resolver — registered via `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`. Every bean is `@ConditionalOnMissingBean` so a consumer can override any piece.

**Tech Stack:** Java 21, Spring Boot 3.3.4 (`spring-boot-autoconfigure`, `spring-boot-starter-oauth2-resource-server`, Spring Security's `NimbusJwtDecoder`), JUnit 5, `ApplicationContextRunner` for autoconfiguration tests, JDK's built-in `com.sun.net.httpserver.HttpServer` + Nimbus JOSE (already transitive) for a Docker-free end-to-end test.

**Spec:** `docs/superpowers/specs/2026-09-11-auth-5-security-commons-design.md`

## Global Constraints

- Module lives at `security-commons/` in `hackaton-fiap-x-auth-service`, as a **standalone** Maven project — do not touch the root `pom.xml`, `Dockerfile`, or `docker-compose.yml`.
- groupId `br.com.fiap.hackaton.security`, artifactId `security-commons`, Java base package `br.com.fiap.hackaton.security.commons`.
- Property prefix `security.jwt` (`jwks-uri` required to activate, `issuer` optional, `public-endpoints` optional with a default list).
- No Testcontainers/Docker anywhere in this module — `ApplicationContextRunner` for autoconfiguration behavior, a plain `com.sun.net.httpserver.HttpServer` JWKS stub for the one end-to-end test.
- Do not touch the `hackaton-fiap-x-video-service` repository — out of scope for this card (confirmed with the user).
- Java 21, Spring Boot 3.3.4 (matches both `auth-service` and `video-service`).
- Formatting: Spotless with `googleJavaFormat` 1.23.0 and `importOrder java,javax,org,com` — same config as the root `pom.xml`. In practice, this repo's existing files use one unmodified alphabetically-sorted import block with **no blank lines** between groups, and that already satisfies `spotless:check`; follow that same shape (do not manually insert blank-line import groups).
- Every new class gets a test; every task ends green (`mvn -f security-commons/pom.xml test`) before moving on.

---

## File Structure

```
security-commons/
  pom.xml
  README.md
  src/main/java/br/com/fiap/hackaton/security/commons/
    SecurityCommonsProperties.java
    SubjectIsUuidValidator.java
    ProblemDetailAuthEntryPoint.java
    CurrentUserId.java
    CurrentUserIdArgumentResolver.java
    ResourceServerAutoConfiguration.java
    WebMvcAutoConfiguration.java
  src/main/resources/META-INF/spring/
    org.springframework.boot.autoconfigure.AutoConfiguration.imports
  src/test/java/br/com/fiap/hackaton/security/commons/
    SecurityCommonsPropertiesTest.java
    SubjectIsUuidValidatorTest.java
    ProblemDetailAuthEntryPointTest.java
    CurrentUserIdArgumentResolverTest.java
    ResourceServerAutoConfigurationTest.java
    WebMvcAutoConfigurationTest.java
    AutoConfigurationImportsTest.java
    ResourceServerEndToEndTest.java
.github/workflows/
  publish-security-commons.yml
```

Each `src/main` file above has exactly one responsibility (one autoconfiguration concern, one validator, one responder, one resolver). Tests live 1:1 next to what they test, except `ResourceServerEndToEndTest`, which exercises the whole stack together.

---

### Task 1: Scaffold the `security-commons` Maven module

**Files:**
- Create: `security-commons/pom.xml`
- Create: `security-commons/.gitignore` (reuse root's ignore rules for `target/`)

**Interfaces:**
- Produces: a buildable, empty Maven module at `security-commons/`, Java 21, importing the Spring Boot 3.3.4 BOM, with Spotless/Enforcer/JaCoCo configured the same way as the root `pom.xml`.

- [ ] **Step 1: Write `security-commons/pom.xml`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>br.com.fiap.hackaton.security</groupId>
    <artifactId>security-commons</artifactId>
    <version>1.0.0-SNAPSHOT</version>
    <packaging>jar</packaging>
    <name>security-commons</name>
    <description>Spring Boot autoconfiguration for a JWKS-based OAuth2 Resource Server, shared across FIAP-X services.</description>

    <properties>
        <java.version>21</java.version>
        <maven.compiler.release>21</maven.compiler.release>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <spring-boot.version>3.3.4</spring-boot.version>
        <jacoco.version>0.8.11</jacoco.version>
        <spotless.version>3.10.0</spotless.version>
    </properties>

    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-dependencies</artifactId>
                <version>${spring-boot.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-autoconfigure</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-configuration-processor</artifactId>
            <optional>true</optional>
        </dependency>
        <!-- Provided by any consuming Spring MVC application; not bundled -->
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-webmvc</artifactId>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>jakarta.servlet</groupId>
            <artifactId>jakarta.servlet-api</artifactId>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <scope>provided</scope>
        </dependency>
        <!-- Test: spring-boot-starter-test alone covers unit/context-runner tests.
             provided-scope spring-webmvc/servlet-api/jackson-databind above are already
             visible on the test classpath — do NOT redeclare them here with scope=test;
             Maven keeps only the LAST declaration of a given groupId:artifactId and would
             silently drop the provided one, breaking src/main compilation. -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <!-- Only Task 9's end-to-end test needs a real embedded servlet container;
             every other test uses WebApplicationContextRunner (no container). -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.13.0</version>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>3.2.5</version>
            </plugin>

            <!-- JaCoCo -->
            <plugin>
                <groupId>org.jacoco</groupId>
                <artifactId>jacoco-maven-plugin</artifactId>
                <version>${jacoco.version}</version>
                <executions>
                    <execution>
                        <id>default-prepare-agent</id>
                        <goals><goal>prepare-agent</goal></goals>
                    </execution>
                    <execution>
                        <id>default-report</id>
                        <phase>verify</phase>
                        <goals><goal>report</goal></goals>
                    </execution>
                </executions>
            </plugin>

            <!-- Spotless -->
            <plugin>
                <groupId>com.diffplug.spotless</groupId>
                <artifactId>spotless-maven-plugin</artifactId>
                <version>${spotless.version}</version>
                <configuration>
                    <java>
                        <googleJavaFormat>
                            <version>1.23.0</version>
                        </googleJavaFormat>
                        <importOrder>
                            <order>java,javax,org,com</order>
                        </importOrder>
                    </java>
                </configuration>
                <executions>
                    <execution>
                        <goals><goal>check</goal></goals>
                        <phase>verify</phase>
                    </execution>
                </executions>
            </plugin>

            <!-- Enforcer -->
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-enforcer-plugin</artifactId>
                <version>3.4.1</version>
                <executions>
                    <execution>
                        <id>enforce-java</id>
                        <goals><goal>enforce</goal></goals>
                        <configuration>
                            <rules>
                                <requireJavaVersion>
                                    <version>21</version>
                                </requireJavaVersion>
                            </rules>
                        </configuration>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
```

- [ ] **Step 2: Write `security-commons/.gitignore`**

```
target/
```

- [ ] **Step 3: Verify the empty module builds**

Run (from repo root, with `JAVA_HOME` pointed at a JDK 21):
```bash
./mvnw -f security-commons/pom.xml -q validate
```
Expected: exits 0, no output (an empty module with no source files still validates cleanly).

- [ ] **Step 4: Commit**

```bash
git add security-commons/pom.xml security-commons/.gitignore
git commit -m "chore(auth-5): scaffold security-commons Maven module"
```

---

### Task 2: `SecurityCommonsProperties`

**Files:**
- Create: `security-commons/src/main/java/br/com/fiap/hackaton/security/commons/SecurityCommonsProperties.java`
- Test: `security-commons/src/test/java/br/com/fiap/hackaton/security/commons/SecurityCommonsPropertiesTest.java`

**Interfaces:**
- Produces: `record SecurityCommonsProperties(String jwksUri, String issuer, List<String> publicEndpoints)`, `@ConfigurationProperties(prefix = "security.jwt")`. Compact constructor defaults `publicEndpoints` to `SecurityCommonsProperties.DEFAULT_PUBLIC_ENDPOINTS` when null or empty.

- [ ] **Step 1: Write the failing test**

```java
package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class SecurityCommonsPropertiesTest {

  @Test
  void defaultsPublicEndpointsWhenNullIsGiven() {
    var properties = new SecurityCommonsProperties("https://issuer/jwks.json", "fiapx-auth", null);

    assertThat(properties.publicEndpoints())
        .containsExactlyInAnyOrder(
            "/actuator/health",
            "/actuator/health/**",
            "/actuator/info",
            "/actuator/prometheus",
            "/api-docs",
            "/api-docs/**",
            "/swagger-ui.html",
            "/swagger-ui/**");
  }

  @Test
  void defaultsPublicEndpointsWhenEmptyListIsGiven() {
    var properties = new SecurityCommonsProperties("https://issuer/jwks.json", null, List.of());

    assertThat(properties.publicEndpoints()).isNotEmpty();
  }

  @Test
  void keepsExplicitPublicEndpointsWhenProvided() {
    var properties =
        new SecurityCommonsProperties(
            "https://issuer/jwks.json", null, List.of("/custom-health"));

    assertThat(properties.publicEndpoints()).containsExactly("/custom-health");
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=SecurityCommonsPropertiesTest`
Expected: FAIL — compile error, `SecurityCommonsProperties` does not exist.

- [ ] **Step 3: Write the implementation**

```java
package br.com.fiap.hackaton.security.commons;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.jwt")
public record SecurityCommonsProperties(String jwksUri, String issuer, List<String> publicEndpoints) {

  static final List<String> DEFAULT_PUBLIC_ENDPOINTS =
      List.of(
          "/actuator/health",
          "/actuator/health/**",
          "/actuator/info",
          "/actuator/prometheus",
          "/api-docs",
          "/api-docs/**",
          "/swagger-ui.html",
          "/swagger-ui/**");

  public SecurityCommonsProperties {
    if (publicEndpoints == null || publicEndpoints.isEmpty()) {
      publicEndpoints = DEFAULT_PUBLIC_ENDPOINTS;
    }
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=SecurityCommonsPropertiesTest`
Expected: PASS, 3 tests green.

- [ ] **Step 5: Commit**

```bash
git add security-commons/src/main/java/br/com/fiap/hackaton/security/commons/SecurityCommonsProperties.java security-commons/src/test/java/br/com/fiap/hackaton/security/commons/SecurityCommonsPropertiesTest.java
git commit -m "feat(auth-5): add SecurityCommonsProperties"
```

---

### Task 3: `SubjectIsUuidValidator`

**Files:**
- Create: `security-commons/src/main/java/br/com/fiap/hackaton/security/commons/SubjectIsUuidValidator.java`
- Test: `security-commons/src/test/java/br/com/fiap/hackaton/security/commons/SubjectIsUuidValidatorTest.java`

**Interfaces:**
- Consumes: `org.springframework.security.oauth2.jwt.Jwt` (from `spring-boot-starter-oauth2-resource-server`).
- Produces: `class SubjectIsUuidValidator implements OAuth2TokenValidator<Jwt>` with `OAuth2TokenValidatorResult validate(Jwt token)`.

- [ ] **Step 1: Write the failing test**

```java
package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class SubjectIsUuidValidatorTest {

  private final SubjectIsUuidValidator validator = new SubjectIsUuidValidator();

  @Test
  void succeedsWhenSubjectIsAValidUuid() {
    Jwt jwt = mock(Jwt.class);
    when(jwt.getSubject()).thenReturn("3fa85f64-5717-4562-b3fc-2c963f66afa6");

    assertThat(validator.validate(jwt).hasErrors()).isFalse();
  }

  @Test
  void failsWhenSubjectIsNotAUuid() {
    Jwt jwt = mock(Jwt.class);
    when(jwt.getSubject()).thenReturn("not-a-uuid");

    assertThat(validator.validate(jwt).hasErrors()).isTrue();
  }

  @Test
  void failsWhenSubjectIsBlank() {
    Jwt jwt = mock(Jwt.class);
    when(jwt.getSubject()).thenReturn("  ");

    assertThat(validator.validate(jwt).hasErrors()).isTrue();
  }

  @Test
  void failsWhenSubjectIsNull() {
    Jwt jwt = mock(Jwt.class);
    when(jwt.getSubject()).thenReturn(null);

    assertThat(validator.validate(jwt).hasErrors()).isTrue();
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=SubjectIsUuidValidatorTest`
Expected: FAIL — compile error, `SubjectIsUuidValidator` does not exist. (If Mockito is missing from the classpath the failure will instead be a `ClassNotFoundException` for `org.mockito.Mockito` — `spring-boot-starter-test` already brings Mockito, so this should not happen; if it does, re-check Task 1's `pom.xml`.)

- [ ] **Step 3: Write the implementation**

```java
package br.com.fiap.hackaton.security.commons;

import java.util.UUID;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class SubjectIsUuidValidator implements OAuth2TokenValidator<Jwt> {

  private static final OAuth2Error INVALID_SUBJECT =
      new OAuth2Error("invalid_token", "The sub claim must be a user UUID", null);

  @Override
  public OAuth2TokenValidatorResult validate(Jwt token) {
    String subject = token.getSubject();
    if (subject == null || subject.isBlank()) {
      return OAuth2TokenValidatorResult.failure(INVALID_SUBJECT);
    }
    try {
      UUID.fromString(subject);
      return OAuth2TokenValidatorResult.success();
    } catch (IllegalArgumentException invalidUuid) {
      return OAuth2TokenValidatorResult.failure(INVALID_SUBJECT);
    }
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=SubjectIsUuidValidatorTest`
Expected: PASS, 4 tests green.

- [ ] **Step 5: Commit**

```bash
git add security-commons/src/main/java/br/com/fiap/hackaton/security/commons/SubjectIsUuidValidator.java security-commons/src/test/java/br/com/fiap/hackaton/security/commons/SubjectIsUuidValidatorTest.java
git commit -m "feat(auth-5): add SubjectIsUuidValidator"
```

---

### Task 4: `ProblemDetailAuthEntryPoint`

**Files:**
- Create: `security-commons/src/main/java/br/com/fiap/hackaton/security/commons/ProblemDetailAuthEntryPoint.java`
- Test: `security-commons/src/test/java/br/com/fiap/hackaton/security/commons/ProblemDetailAuthEntryPointTest.java`

**Interfaces:**
- Consumes: `com.fasterxml.jackson.databind.ObjectMapper` (constructor param).
- Produces: `class ProblemDetailAuthEntryPoint implements AuthenticationEntryPoint, AccessDeniedHandler`, `public static final URI UNAUTHORIZED_TYPE`, `public static final URI FORBIDDEN_TYPE`, constructor `ProblemDetailAuthEntryPoint(ObjectMapper objectMapper)`.

- [ ] **Step 1: Write the failing test**

```java
package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;

class ProblemDetailAuthEntryPointTest {

  private final ObjectMapper objectMapper = new ObjectMapper();
  private final ProblemDetailAuthEntryPoint responder =
      new ProblemDetailAuthEntryPoint(objectMapper);

  @Test
  void commenceWritesA401ProblemDetail() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/videos");
    MockHttpServletResponse response = new MockHttpServletResponse();

    responder.commence(request, response, new BadCredentialsException("bad token"));

    assertThat(response.getStatus()).isEqualTo(401);
    JsonNode body = objectMapper.readTree(response.getContentAsString());
    assertThat(body.get("status").asInt()).isEqualTo(401);
    assertThat(body.get("type").asText()).isEqualTo("urn:problem-type:unauthorized");
    assertThat(body.get("instance").asText()).isEqualTo("/videos");
  }

  @Test
  void handleWritesA403ProblemDetail() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("DELETE", "/videos/1");
    MockHttpServletResponse response = new MockHttpServletResponse();

    responder.handle(request, response, new AccessDeniedException("nope"));

    assertThat(response.getStatus()).isEqualTo(403);
    JsonNode body = objectMapper.readTree(response.getContentAsString());
    assertThat(body.get("status").asInt()).isEqualTo(403);
    assertThat(body.get("type").asText()).isEqualTo("urn:problem-type:forbidden");
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=ProblemDetailAuthEntryPointTest`
Expected: FAIL — compile error, `ProblemDetailAuthEntryPoint` does not exist.

- [ ] **Step 3: Write the implementation**

```java
package br.com.fiap.hackaton.security.commons;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

public class ProblemDetailAuthEntryPoint implements AuthenticationEntryPoint, AccessDeniedHandler {

  public static final URI UNAUTHORIZED_TYPE = URI.create("urn:problem-type:unauthorized");
  public static final URI FORBIDDEN_TYPE = URI.create("urn:problem-type:forbidden");

  private final ObjectMapper objectMapper;

  public ProblemDetailAuthEntryPoint(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  @Override
  public void commence(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
      throws IOException {
    write(
        request,
        response,
        HttpStatus.UNAUTHORIZED,
        UNAUTHORIZED_TYPE,
        "Unauthorized",
        "Missing, expired or invalid token.");
  }

  @Override
  public void handle(
      HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception)
      throws IOException {
    write(
        request,
        response,
        HttpStatus.FORBIDDEN,
        FORBIDDEN_TYPE,
        "Forbidden",
        "The token does not allow this operation.");
  }

  private void write(
      HttpServletRequest request,
      HttpServletResponse response,
      HttpStatus status,
      URI type,
      String title,
      String detail)
      throws IOException {
    ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
    problem.setType(type);
    problem.setTitle(title);
    problem.setInstance(URI.create(request.getRequestURI()));
    problem.setProperty("timestamp", Instant.now());

    response.setStatus(status.value());
    response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    objectMapper.writeValue(response.getWriter(), problem);
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=ProblemDetailAuthEntryPointTest`
Expected: PASS, 2 tests green.

- [ ] **Step 5: Commit**

```bash
git add security-commons/src/main/java/br/com/fiap/hackaton/security/commons/ProblemDetailAuthEntryPoint.java security-commons/src/test/java/br/com/fiap/hackaton/security/commons/ProblemDetailAuthEntryPointTest.java
git commit -m "feat(auth-5): add ProblemDetailAuthEntryPoint"
```

---

### Task 5: `CurrentUserId` + `CurrentUserIdArgumentResolver`

**Files:**
- Create: `security-commons/src/main/java/br/com/fiap/hackaton/security/commons/CurrentUserId.java`
- Create: `security-commons/src/main/java/br/com/fiap/hackaton/security/commons/CurrentUserIdArgumentResolver.java`
- Test: `security-commons/src/test/java/br/com/fiap/hackaton/security/commons/CurrentUserIdArgumentResolverTest.java`

**Interfaces:**
- Produces: `@interface CurrentUserId` (`@Target(PARAMETER)`, `@Retention(RUNTIME)`); `class CurrentUserIdArgumentResolver implements HandlerMethodArgumentResolver` with `boolean supportsParameter(MethodParameter)` and `UUID resolveArgument(MethodParameter, ModelAndViewContainer, NativeWebRequest, WebDataBinderFactory)`.

- [ ] **Step 1: Write the failing test**

```java
package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

class CurrentUserIdArgumentResolverTest {

  private final CurrentUserIdArgumentResolver resolver = new CurrentUserIdArgumentResolver();

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void supportsUuidParameterAnnotatedWithCurrentUserId() throws NoSuchMethodException {
    MethodParameter parameter = annotatedParameter();

    assertThat(resolver.supportsParameter(parameter)).isTrue();
  }

  @Test
  void doesNotSupportParameterWithoutTheAnnotation() throws NoSuchMethodException {
    Method method = SampleController.class.getMethod("withoutAnnotation", UUID.class);
    MethodParameter parameter = new MethodParameter(method, 0);

    assertThat(resolver.supportsParameter(parameter)).isFalse();
  }

  @Test
  void resolvesUuidFromTheAuthenticatedJwtSubject() throws Exception {
    UUID userId = UUID.randomUUID();
    Jwt jwt = mock(Jwt.class);
    when(jwt.getSubject()).thenReturn(userId.toString());
    SecurityContextHolder.getContext()
        .setAuthentication(new TestingAuthenticationToken(jwt, null));

    UUID resolved = resolver.resolveArgument(annotatedParameter(), null, null, null);

    assertThat(resolved).isEqualTo(userId);
  }

  @Test
  void throws401WhenThereIsNoAuthentication() {
    assertThatThrownBy(() -> resolver.resolveArgument(annotatedParameter(), null, null, null))
        .isInstanceOf(ResponseStatusException.class)
        .hasMessageContaining("401");
  }

  private static MethodParameter annotatedParameter() throws NoSuchMethodException {
    Method method = SampleController.class.getMethod("withAnnotation", UUID.class);
    return new MethodParameter(method, 0);
  }

  static class SampleController {
    public void withAnnotation(@CurrentUserId UUID userId) {}

    public void withoutAnnotation(UUID userId) {}
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=CurrentUserIdArgumentResolverTest`
Expected: FAIL — compile error, `CurrentUserId`/`CurrentUserIdArgumentResolver` do not exist.

- [ ] **Step 3: Write `CurrentUserId.java`**

```java
package br.com.fiap.hackaton.security.commons;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface CurrentUserId {}
```

- [ ] **Step 4: Write `CurrentUserIdArgumentResolver.java`**

```java
package br.com.fiap.hackaton.security.commons;

import java.util.UUID;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.server.ResponseStatusException;

public class CurrentUserIdArgumentResolver implements HandlerMethodArgumentResolver {

  @Override
  public boolean supportsParameter(MethodParameter parameter) {
    return parameter.hasParameterAnnotation(CurrentUserId.class)
        && UUID.class.equals(parameter.getParameterType());
  }

  @Override
  public UUID resolveArgument(
      MethodParameter parameter,
      ModelAndViewContainer container,
      NativeWebRequest request,
      WebDataBinderFactory binderFactory) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Request has no valid token");
    }
    return UUID.fromString(jwt.getSubject());
  }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=CurrentUserIdArgumentResolverTest`
Expected: PASS, 4 tests green.

- [ ] **Step 6: Commit**

```bash
git add security-commons/src/main/java/br/com/fiap/hackaton/security/commons/CurrentUserId.java security-commons/src/main/java/br/com/fiap/hackaton/security/commons/CurrentUserIdArgumentResolver.java security-commons/src/test/java/br/com/fiap/hackaton/security/commons/CurrentUserIdArgumentResolverTest.java
git commit -m "feat(auth-5): add CurrentUserId argument resolver"
```

---

### Task 6: `ResourceServerAutoConfiguration`

**Files:**
- Create: `security-commons/src/main/java/br/com/fiap/hackaton/security/commons/ResourceServerAutoConfiguration.java`
- Test: `security-commons/src/test/java/br/com/fiap/hackaton/security/commons/ResourceServerAutoConfigurationTest.java`

**Interfaces:**
- Consumes: `SecurityCommonsProperties` (Task 2), `SubjectIsUuidValidator` (Task 3), `ProblemDetailAuthEntryPoint` (Task 4).
- Produces: `@AutoConfiguration @AutoConfigureBefore(SecurityAutoConfiguration.class) class ResourceServerAutoConfiguration` with beans `JwtDecoder jwtDecoder(SecurityCommonsProperties)`, `ProblemDetailAuthEntryPoint problemDetailAuthEntryPoint(ObjectMapper)`, `SecurityFilterChain securityFilterChain(HttpSecurity, JwtDecoder, SecurityCommonsProperties, ProblemDetailAuthEntryPoint)`.

A note on how this task's test was arrived at: building a real `SecurityFilterChain` bean needs a live `HttpSecurity`, which only exists when Spring Security's own web-security scaffolding (`org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration`) is active, and MVC-aware `requestMatchers(String...)` additionally needs an `HandlerMappingIntrospector` bean, which only exists when `org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration` (Spring Boot's own — not this module's `WebMvcAutoConfiguration` from Task 7) is active too. So the test below uses `WebApplicationContextRunner` (not plain `ApplicationContextRunner`) with both of those registered alongside this module's own autoconfiguration — that combination is what a real consuming Spring Boot web application always has present, so it is a faithful (if lighter-weight) stand-in for Task 9's full end-to-end test.

- [ ] **Step 1: Write the failing test**

```java
package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

class ResourceServerAutoConfigurationTest {

  private final WebApplicationContextRunner contextRunner =
      new WebApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(
                  WebMvcAutoConfiguration.class,
                  SecurityAutoConfiguration.class,
                  ResourceServerAutoConfiguration.class))
          .withBean(ObjectMapper.class, ObjectMapper::new);

  @Test
  void doesNothingWithoutAJwksUriProperty() {
    contextRunner.run(
        (AssertableWebApplicationContext context) -> {
          assertThat(context).doesNotHaveBean(JwtDecoder.class);
          assertThat(context).doesNotHaveBean(ProblemDetailAuthEntryPoint.class);
        });
  }

  @Test
  void registersDecoderAndFilterChainWhenJwksUriIsSet() {
    contextRunner
        .withPropertyValues("security.jwt.jwks-uri=https://issuer.example/jwks.json")
        .run(
            (AssertableWebApplicationContext context) -> {
              assertThat(context).hasSingleBean(JwtDecoder.class);
              assertThat(context).hasSingleBean(SecurityFilterChain.class);
              assertThat(context).hasSingleBean(ProblemDetailAuthEntryPoint.class);
            });
  }

  @Test
  void backsOffWhenAUserSuppliedJwtDecoderExists() {
    contextRunner
        .withPropertyValues("security.jwt.jwks-uri=https://issuer.example/jwks.json")
        .withUserConfiguration(CustomJwtDecoderConfig.class)
        .run(
            (AssertableWebApplicationContext context) -> {
              assertThat(context).hasSingleBean(JwtDecoder.class);
              assertThat(context.getBean(JwtDecoder.class))
                  .isSameAs(context.getBean(CustomJwtDecoderConfig.class).decoder);
            });
  }

  @Configuration
  static class CustomJwtDecoderConfig {
    final JwtDecoder decoder =
        token -> {
          throw new UnsupportedOperationException("test double");
        };

    @Bean
    JwtDecoder jwtDecoder() {
      return decoder;
    }
  }
}
```

Test 1 deliberately does not assert on `SecurityFilterChain` absence: with `SecurityAutoConfiguration` active and no `jwks-uri` property, Spring Boot's own `defaultSecurityFilterChain` fallback bean fills that role instead (that is expected, standard Spring Boot behavior, not a bug) — the meaningful assertion is that *this module's* beans (`JwtDecoder`, `ProblemDetailAuthEntryPoint`) are absent.

- [ ] **Step 2: Run test to verify it fails**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=ResourceServerAutoConfigurationTest`
Expected: FAIL — compile error, `ResourceServerAutoConfiguration` does not exist.

- [ ] **Step 3: Write the implementation**

```java
package br.com.fiap.hackaton.security.commons;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;

@AutoConfiguration
@AutoConfigureBefore(SecurityAutoConfiguration.class)
@EnableConfigurationProperties(SecurityCommonsProperties.class)
@ConditionalOnClass({SecurityFilterChain.class, JwtDecoder.class})
@ConditionalOnProperty(prefix = "security.jwt", name = "jwks-uri")
public class ResourceServerAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public JwtDecoder jwtDecoder(SecurityCommonsProperties properties) {
    NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(properties.jwksUri()).build();
    decoder.setJwtValidator(buildValidator(properties.issuer()));
    return decoder;
  }

  static OAuth2TokenValidator<Jwt> buildValidator(String issuer) {
    OAuth2TokenValidator<Jwt> defaults =
        StringUtils.hasText(issuer)
            ? JwtValidators.createDefaultWithIssuer(issuer)
            : JwtValidators.createDefault();
    return new DelegatingOAuth2TokenValidator<>(defaults, new SubjectIsUuidValidator());
  }

  @Bean
  @ConditionalOnMissingBean(ProblemDetailAuthEntryPoint.class)
  public ProblemDetailAuthEntryPoint problemDetailAuthEntryPoint(ObjectMapper objectMapper) {
    return new ProblemDetailAuthEntryPoint(objectMapper);
  }

  @Bean
  @ConditionalOnMissingBean(SecurityFilterChain.class)
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      JwtDecoder jwtDecoder,
      SecurityCommonsProperties properties,
      ProblemDetailAuthEntryPoint responder)
      throws Exception {
    String[] publicEndpoints = properties.publicEndpoints().toArray(new String[0]);
    return http.csrf(csrf -> csrf.disable())
        .cors(cors -> cors.disable())
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(
            requests ->
                requests
                    .requestMatchers(HttpMethod.OPTIONS, "/**")
                    .permitAll()
                    .requestMatchers(publicEndpoints)
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .oauth2ResourceServer(
            oauth2 ->
                oauth2
                    .jwt(jwt -> jwt.decoder(jwtDecoder))
                    .authenticationEntryPoint(responder)
                    .accessDeniedHandler(responder))
        .exceptionHandling(
            exceptions ->
                exceptions
                    .authenticationEntryPoint(responder)
                    .accessDeniedHandler(responder))
        .build();
  }
}
```

`@AutoConfigureBefore(SecurityAutoConfiguration.class)` is required, not optional: without it, Spring Boot processes its own `SecurityAutoConfiguration` first, which registers a `defaultSecurityFilterChain` fallback bean (`httpBasic` + `formLogin`, everything authenticated) — that bean satisfies `@ConditionalOnMissingBean(SecurityFilterChain.class)` before this class's own `securityFilterChain` bean method ever runs, so *this* bean silently backs off instead of Boot's default backing off. The symptom if this annotation is missing or wrong: requests get redirected to Spring Boot's default HTML "Please sign in" login page instead of being validated against the JWKS.

- [ ] **Step 4: Run test to verify it passes**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=ResourceServerAutoConfigurationTest`
Expected: PASS, 3 tests green.

- [ ] **Step 5: Commit**

```bash
git add security-commons/src/main/java/br/com/fiap/hackaton/security/commons/ResourceServerAutoConfiguration.java security-commons/src/test/java/br/com/fiap/hackaton/security/commons/ResourceServerAutoConfigurationTest.java
git commit -m "feat(auth-5): add ResourceServerAutoConfiguration"
```

---

### Task 7: `WebMvcAutoConfiguration`

**Files:**
- Create: `security-commons/src/main/java/br/com/fiap/hackaton/security/commons/WebMvcAutoConfiguration.java`
- Test: `security-commons/src/test/java/br/com/fiap/hackaton/security/commons/WebMvcAutoConfigurationTest.java`

**Interfaces:**
- Consumes: `CurrentUserIdArgumentResolver` (Task 5).
- Produces: `@AutoConfiguration class WebMvcAutoConfiguration` with beans `CurrentUserIdArgumentResolver currentUserIdArgumentResolver()` and `WebMvcConfigurer securityCommonsWebMvcConfigurer(CurrentUserIdArgumentResolver)`.

- [ ] **Step 1: Write the failing test**

```java
package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

class WebMvcAutoConfigurationTest {

  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(WebMvcAutoConfiguration.class));

  @Test
  void registersTheCurrentUserIdArgumentResolver() {
    contextRunner.run(
        (AssertableApplicationContext context) -> {
          assertThat(context).hasSingleBean(CurrentUserIdArgumentResolver.class);
          WebMvcConfigurer configurer = context.getBean(WebMvcConfigurer.class);
          List<HandlerMethodArgumentResolver> resolvers = new ArrayList<>();
          configurer.addArgumentResolvers(resolvers);
          assertThat(resolvers).hasSize(1).first().isInstanceOf(CurrentUserIdArgumentResolver.class);
        });
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=WebMvcAutoConfigurationTest`
Expected: FAIL — compile error, `WebMvcAutoConfiguration` does not exist.

- [ ] **Step 3: Write the implementation**

```java
package br.com.fiap.hackaton.security.commons;

import java.util.List;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@AutoConfiguration
@ConditionalOnClass(WebMvcConfigurer.class)
public class WebMvcAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public CurrentUserIdArgumentResolver currentUserIdArgumentResolver() {
    return new CurrentUserIdArgumentResolver();
  }

  @Bean
  public WebMvcConfigurer securityCommonsWebMvcConfigurer(CurrentUserIdArgumentResolver resolver) {
    return new WebMvcConfigurer() {
      @Override
      public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(resolver);
      }
    };
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=WebMvcAutoConfigurationTest`
Expected: PASS, 1 test green.

- [ ] **Step 5: Commit**

```bash
git add security-commons/src/main/java/br/com/fiap/hackaton/security/commons/WebMvcAutoConfiguration.java security-commons/src/test/java/br/com/fiap/hackaton/security/commons/WebMvcAutoConfigurationTest.java
git commit -m "feat(auth-5): add WebMvcAutoConfiguration"
```

---

### Task 8: Register both autoconfigurations

**Files:**
- Create: `security-commons/src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`
- Test: `security-commons/src/test/java/br/com/fiap/hackaton/security/commons/AutoConfigurationImportsTest.java`

**Interfaces:**
- Consumes: `ResourceServerAutoConfiguration` (Task 6), `WebMvcAutoConfiguration` (Task 7).
- Produces: a classpath resource that Spring Boot's autoconfiguration import mechanism reads automatically — this is what makes "just add the dependency" true; no consumer-side `@Import` needed.

- [ ] **Step 1: Write the failing test**

```java
package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.StreamUtils;

class AutoConfigurationImportsTest {

  @Test
  void listsBothAutoConfigurationClasses() throws IOException {
    ClassPathResource resource =
        new ClassPathResource(
            "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports");

    String content;
    try (InputStream in = resource.getInputStream()) {
      content = StreamUtils.copyToString(in, StandardCharsets.UTF_8);
    }

    List<String> lines = content.lines().map(String::trim).filter(line -> !line.isBlank()).toList();

    assertThat(lines)
        .containsExactlyInAnyOrder(
            ResourceServerAutoConfiguration.class.getName(), WebMvcAutoConfiguration.class.getName());
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=AutoConfigurationImportsTest`
Expected: FAIL — `IOException`/resource not found, the imports file does not exist yet.

- [ ] **Step 3: Write the imports file**

```
br.com.fiap.hackaton.security.commons.ResourceServerAutoConfiguration
br.com.fiap.hackaton.security.commons.WebMvcAutoConfiguration
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=AutoConfigurationImportsTest`
Expected: PASS, 1 test green.

- [ ] **Step 5: Commit**

```bash
git add "security-commons/src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports" security-commons/src/test/java/br/com/fiap/hackaton/security/commons/AutoConfigurationImportsTest.java
git commit -m "feat(auth-5): register security-commons autoconfigurations"
```

---

### Task 9: End-to-end proof (no Docker)

**Files:**
- Test: `security-commons/src/test/java/br/com/fiap/hackaton/security/commons/ResourceServerEndToEndTest.java`

**Interfaces:**
- Consumes: everything from Tasks 2–8 — this is the proof they work together inside a real Spring Boot web application context.
- Produces: nothing new for later tasks; this is the acceptance-criteria proof (401 without a token, 200 + correct `userId` with one, JWKS served with no Docker).

- [ ] **Step 1: Write the end-to-end test**

```java
package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    classes = ResourceServerEndToEndTest.TestApp.class)
class ResourceServerEndToEndTest {

  private static KeyPair keyPair;
  private static HttpServer jwksServer;
  private static int jwksPort;

  @LocalServerPort private int appPort;

  @Autowired private TestRestTemplate restTemplate;

  @BeforeAll
  static void startJwksStub() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    keyPair = generator.generateKeyPair();

    RSAKey jwk =
        new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .privateKey((RSAPrivateKey) keyPair.getPrivate())
            .keyID("test-key")
            .build()
            .toPublicJWK();
    String jwksJson = "{\"keys\":[" + jwk.toJSONString() + "]}";

    jwksServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    jwksServer.createContext(
        "/.well-known/jwks.json",
        exchange -> {
          byte[] body = jwksJson.getBytes(StandardCharsets.UTF_8);
          exchange.getResponseHeaders().add("Content-Type", "application/json");
          exchange.sendResponseHeaders(200, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    jwksServer.start();
    jwksPort = jwksServer.getAddress().getPort();
  }

  @AfterAll
  static void stopJwksStub() {
    jwksServer.stop(0);
  }

  @DynamicPropertySource
  static void jwksUri(DynamicPropertyRegistry registry) {
    registry.add(
        "security.jwt.jwks-uri",
        () -> "http://localhost:" + jwksPort + "/.well-known/jwks.json");
  }

  @Test
  void requestWithoutTokenReturns401() {
    ResponseEntity<String> response =
        restTemplate.getForEntity(url("/me"), String.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  void requestWithValidTokenReturns200WithUserIdFromSubject() throws Exception {
    UUID userId = UUID.randomUUID();
    String token = signToken(userId.toString());

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    ResponseEntity<String> response =
        restTemplate.exchange(url("/me"), HttpMethod.GET, new HttpEntity<>(headers), String.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).isEqualTo(userId.toString());
  }

  @Test
  void requestWithNonUuidSubjectReturns401() throws Exception {
    String token = signToken("not-a-uuid");

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    ResponseEntity<String> response =
        restTemplate.exchange(url("/me"), HttpMethod.GET, new HttpEntity<>(headers), String.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  private String url(String path) {
    return "http://localhost:" + appPort + path;
  }

  private static String signToken(String subject) throws Exception {
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject(subject)
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(300)))
            .build();
    SignedJWT jwt =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test-key").build(), claims);
    jwt.sign(new RSASSASigner(keyPair.getPrivate()));
    return jwt.serialize();
  }

  @SpringBootApplication
  static class TestApp {
    @RestController
    static class MeController {
      @GetMapping("/me")
      String me(@CurrentUserId UUID userId) {
        return userId.toString();
      }
    }
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=ResourceServerEndToEndTest`
Expected: this test is new, not a red/green pair against not-yet-written production code (everything it depends on already exists from Tasks 2–8) — so "failing first" here means confirming it does NOT already pass for the wrong reason. It should FAIL before this point simply because the file doesn't exist yet. If it fails for a compile error, `com.nimbusds.*` classes come transitively via `spring-boot-starter-oauth2-resource-server` → `spring-security-oauth2-jose` → `nimbus-jose-jwt`, already on the test classpath from Task 1 — a compile error there means a typo, not a missing dependency. If it fails for any other reason, treat that as a real bug, not something to paper over.

- [ ] **Step 3: Run again until all 3 tests pass**

Run: `./mvnw -f security-commons/pom.xml -q test -Dtest=ResourceServerEndToEndTest`
Expected: PASS, 3 tests green — no Docker, no Testcontainers involved.

- [ ] **Step 4: Commit**

```bash
git add security-commons/src/test/java/br/com/fiap/hackaton/security/commons/ResourceServerEndToEndTest.java
git commit -m "test(auth-5): add end-to-end Resource Server proof, no Docker required"
```

---

### Task 10: Publish to GitHub Packages

**Files:**
- Modify: `security-commons/pom.xml` (add `<distributionManagement>`)
- Create: `.github/workflows/publish-security-commons.yml`

**Interfaces:**
- Produces: on push to `main` touching `security-commons/**`, the module is built and `deploy`ed to this repo's GitHub Packages Maven registry.

- [ ] **Step 1: Add `<distributionManagement>` to `security-commons/pom.xml`**

Insert right after the closing `</properties>` tag:

```xml
    <distributionManagement>
        <repository>
            <id>github</id>
            <name>GitHub Packages</name>
            <url>https://maven.pkg.github.com/hackaton-FIAP-X/hackaton-fiap-x-auth-service</url>
        </repository>
    </distributionManagement>
```

- [ ] **Step 2: Write `.github/workflows/publish-security-commons.yml`**

```yaml
name: Publish security-commons

on:
  push:
    branches: [main]
    paths:
      - 'security-commons/**'

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'temurin'
          server-id: github
      - name: Publish to GitHub Packages
        run: ./mvnw -f security-commons/pom.xml -B deploy -DskipTests
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

`-DskipTests` here is deliberate: this workflow only fires on `main` after a PR already ran the full test suite as a required check (see Task 11) — deploy should not re-run a full JVM/network-touching test pass, just package and publish what already passed review.

- [ ] **Step 3: Verify the pom change doesn't break the build**

Run: `./mvnw -f security-commons/pom.xml -q test`
Expected: PASS, all prior tests still green (a `<distributionManagement>` addition does not affect `test`).

- [ ] **Step 4: Commit**

```bash
git add security-commons/pom.xml .github/workflows/publish-security-commons.yml
git commit -m "chore(auth-5): publish security-commons to GitHub Packages on main"
```

---

### Task 11: README, full verify, and format check

**Files:**
- Create: `security-commons/README.md`

**Interfaces:**
- Produces: the literal "add a dependency and a property" instructions the acceptance criteria describe, for whoever migrates `video-service` (or `processing-worker`) next.

- [ ] **Step 1: Write `security-commons/README.md`**

```markdown
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
```

- [ ] **Step 2: Run the full module test suite**

Run: `./mvnw -f security-commons/pom.xml -q test`
Expected: PASS, all tests from Tasks 2–9 green together.

- [ ] **Step 3: Apply and verify formatting**

Run:
```bash
./mvnw -f security-commons/pom.xml -q spotless:apply
./mvnw -f security-commons/pom.xml -q spotless:check
```
Expected: `spotless:apply` exits 0 (may rewrite files); `spotless:check` exits 0 with no output afterward. If `spotless:apply` reorders imports into multiple blank-line-separated groups (as it did during AUTH-4), manually collapse each file's imports back into a single alphabetically-sorted block with no blank lines, matching every other file in this repo, then re-run `spotless:check` to confirm it still passes.

- [ ] **Step 4: Full verify (compiles, tests, coverage, format, enforcer all together)**

Run: `./mvnw -f security-commons/pom.xml -q verify`
Expected: PASS, `BUILD SUCCESS`.

- [ ] **Step 5: Commit**

```bash
git add security-commons/README.md
git commit -m "docs(auth-5): add security-commons README"
```

If Step 3 required manual import fixes in any file, stage and commit those separately:
```bash
git add -u security-commons/
git commit -m "style(auth-5): match repo import convention after spotless:apply"
```
