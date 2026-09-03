# AUTH-2: Registro de Usuário com Argon2id + Pepper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implementar `POST /auth/register` no auth-service: recebe nome/e-mail/senha, valida, gera hash Argon2id com pepper (HMAC-SHA256 aplicado antes do Argon2id, segredo fora do banco), persiste o usuário com papel padrão `USER`, retorna 409 em e-mail duplicado, e garante que a senha em texto puro nunca aparece em log nem em qualquer resposta HTTP (sucesso ou erro).

**Architecture:** Um primitivo de criptografia dedicado (`PepperedPasswordEncoder`) decora um `Argon2PasswordEncoder` (Spring Security Crypto): antes de aplicar Argon2id, computa `HMAC-SHA256(chave=pepper, mensagem=senha)` e usa o resultado como entrada do algoritmo — a técnica de pepper recomendada pela OWASP hoje (mais robusta que concatenar `senha+pepper` direto). O pepper é um segredo único da aplicação (não é por usuário, ao contrário do salt), injetado via variável de ambiente `PASSWORD_PEPPER` e sem valor default em produção — a aplicação falha ao subir se ele não estiver definido, em vez de silenciosamente operar sem essa camada de defesa. Como o decorator implementa a mesma interface `PasswordEncoder`, todo o resto do código (camada de serviço, camada web) permanece exatamente igual ao desenho original com BCrypt/Argon2id puro — só a implementação injetada no bean muda.

Camada de serviço (`UserRegistrationService`) concentra a regra de negócio — hash da senha via `PasswordEncoder` e detecção de e-mail duplicado reaproveitando a constraint `uk_users_email` já criada na migration da AUTH-1 (tenta salvar, captura `DataIntegrityViolationException`, remapeia para uma exceção de domínio). Camada web (`AuthController` + `GlobalExceptionHandler`) traduz isso para HTTP: 201 com `UserResponse` (sem senha/hash), 409 em duplicidade, 400 em falha de validação Bean Validation — sem nunca ecoar o valor da senha rejeitada. Dependemos apenas de `spring-security-crypto` (não o starter completo de Spring Security), pois autenticação/login fica para a AUTH-3 e não queremos uma security filter chain travando os demais endpoints agora. `Argon2PasswordEncoder` delega a implementação do algoritmo para Bouncy Castle, que o `spring-security-crypto` declara como dependência opcional — por isso `org.bouncycastle:bcprov-jdk18on` precisa ser adicionado explicitamente, senão a aplicação quebra em runtime (`NoClassDefFoundError`) na primeira chamada ao encoder.

**Tech Stack:** Spring Boot 3.3.4, Spring Data JPA (AUTH-1), Spring Security Crypto + Bouncy Castle (Argon2id), `javax.crypto` (HMAC-SHA256 do próprio JDK, sem dependência extra), Jakarta Bean Validation (já presente via `spring-boot-starter-validation`), Java 21, Postgres via Testcontainers para os testes.

**Spec:** ClickUp AUTH-2 — https://app.clickup.com/t/86e2w9zw8

## Global Constraints

- Endpoint: `POST /auth/register`.
- **Argon2id + Pepper** — hash é `Argon2id(HMAC-SHA256(pepper, senha))`, não `Argon2id(senha)` puro. Parâmetros do Argon2id são os defaults do Spring Security 5.8+ (`Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()`: memória 19456 KiB / 19 MiB, 2 iterações, paralelismo 1, salt 16 bytes, hash 32 bytes), alinhados com a recomendação mínima do OWASP Password Storage Cheat Sheet. Decisão tomada em conversa com o usuário em 2026-09-02, substituindo o "BCrypt com força 10" original do ticket; o ClickUp AUTH-2 foi atualizado para refletir isso (título e critérios de aceite).
- O pepper é lido de `${PASSWORD_PEPPER}` via propriedade `app.security.password-pepper` — **sem default em `src/main/resources/application.yml`**: se a variável de ambiente não estiver definida, a aplicação deve falhar ao subir (fail-fast), nunca operar silenciosamente sem pepper. Para os testes automatizados, um pepper fixo de teste é fornecido via `src/test/resources/application.yml` (arquivo novo, não existe ainda no projeto). Para desenvolvimento local via `docker-compose.yml`, um valor default óbvio (`local-dev-pepper-change-me`) é aceitável, seguindo o mesmo padrão já usado para as credenciais do Postgres na AUTH-1.
- E-mail duplicado retorna **409 Conflict**.
- Validação: `email` deve ter formato de e-mail válido (`@Email`); `password` tem tamanho mínimo de **8 caracteres** (`@Size(min = 8)`) — o ticket não define o número exato; 8 é o piso mínimo padrão de mercado (ex. recomendação NIST), documentado aqui como decisão de design desta tarefa.
- A senha em texto puro **nunca** aparece em log nem em corpo de resposta HTTP — inclusive nas respostas de erro de validação (não usar `getRejectedValue()` do Bean Validation nas respostas).
- Papel padrão do usuário autorregistrado: `UserRole.USER` (não existe endpoint de registro de admin; ticket não menciona escolha de papel no registro).
- Reaproveita a tabela `users` e a constraint `uk_users_email` da migration `V1__create_users_table.sql` (AUTH-1) — nenhuma nova migration é necessária.
- Pacote raiz do projeto: `br.com.fiap.hackaton.auth` (já existente). Novo código: primitivo de criptografia (pepper + Argon2id) em `br.com.fiap.hackaton.auth.security`; wiring do bean em `br.com.fiap.hackaton.auth.config`; domínio de registro em `br.com.fiap.hackaton.auth.user` (mesmo pacote de `User`/`UserRepository`); tratamento de erro HTTP em `br.com.fiap.hackaton.auth.web`.
- Java 21 / Spring Boot 3.3.4 (não alterar).
- Novas dependências `org.springframework.security:spring-security-crypto` e `org.bouncycastle:bcprov-jdk18on` usam a versão gerenciada pelo BOM `spring-boot-starter-parent` — não fixar versão explícita, a menos que o build acuse que o BOM não gerencia `bcprov-jdk18on` (nesse caso, pinar a versão mais recente disponível e registrar isso como desvio no relatório da task). HMAC-SHA256 usa `javax.crypto` puro (já presente no JDK) — nenhuma dependência nova para o pepper em si.

---

## File Structure

- `pom.xml` — adiciona `org.springframework.security:spring-security-crypto` e `org.bouncycastle:bcprov-jdk18on`.
- `src/main/java/br/com/fiap/hackaton/auth/security/PepperedPasswordEncoder.java` — decorator `PasswordEncoder` que aplica HMAC-SHA256(pepper, senha) antes de delegar ao Argon2id.
- `src/main/java/br/com/fiap/hackaton/auth/config/PasswordEncoderConfig.java` — bean `PasswordEncoder` = `PepperedPasswordEncoder` envolvendo `Argon2PasswordEncoder`, injetando o pepper via `@Value`.
- `src/main/resources/application.yml` — adiciona `app.security.password-pepper: ${PASSWORD_PEPPER}` (sem default).
- `src/test/resources/application.yml` — novo arquivo; define um pepper fixo só para os testes.
- `docker-compose.yml` — adiciona `PASSWORD_PEPPER` ao ambiente do serviço `auth-service` (valor default de desenvolvimento).
- `src/main/java/br/com/fiap/hackaton/auth/user/RegisterRequest.java` — DTO de entrada com Bean Validation; `toString()` redige a senha.
- `src/main/java/br/com/fiap/hackaton/auth/user/EmailAlreadyRegisteredException.java` — exceção de domínio para e-mail duplicado.
- `src/main/java/br/com/fiap/hackaton/auth/user/UserRegistrationService.java` — hash da senha + persistência + tradução de `DataIntegrityViolationException` em `EmailAlreadyRegisteredException`.
- `src/main/java/br/com/fiap/hackaton/auth/user/UserResponse.java` — DTO de saída (sem senha/hash).
- `src/main/java/br/com/fiap/hackaton/auth/user/AuthController.java` — `POST /auth/register`.
- `src/main/java/br/com/fiap/hackaton/auth/web/ErrorResponse.java` — DTO de erro genérico (`{message}`), usado no 409.
- `src/main/java/br/com/fiap/hackaton/auth/web/ValidationErrorResponse.java` — DTO de erro de validação (`{message, errors:[{field, message}]}`), usado no 400.
- `src/main/java/br/com/fiap/hackaton/auth/web/GlobalExceptionHandler.java` — `@RestControllerAdvice` mapeando `EmailAlreadyRegisteredException` → 409 e `MethodArgumentNotValidException` → 400.
- `src/test/java/br/com/fiap/hackaton/auth/security/PepperedPasswordEncoderTest.java` — prova que o pepper participa do hash (peppers diferentes produzem hashes que não batem para a mesma senha) e que `matches` funciona corretamente — teste unitário puro, sem Spring context.
- `src/test/java/br/com/fiap/hackaton/auth/user/UserRegistrationServiceTest.java` — prova hash Argon2id+pepper via o bean real, papel padrão `USER`, e exceção em e-mail duplicado, na camada de serviço.
- `src/test/java/br/com/fiap/hackaton/auth/user/AuthControllerRegisterTest.java` — prova o contrato HTTP completo: 201 com hash confirmado no banco, 409 em duplicidade, 400 em e-mail inválido, 400 em senha curta sem ecoar a senha, e ausência da senha em qualquer log durante o registro.

---

### Task 1: Primitivo de criptografia — Argon2id com Pepper (HMAC-SHA256)

**Files:**
- Modify: `pom.xml`
- Create: `src/main/java/br/com/fiap/hackaton/auth/security/PepperedPasswordEncoder.java`
- Create: `src/main/java/br/com/fiap/hackaton/auth/config/PasswordEncoderConfig.java`
- Modify: `src/main/resources/application.yml`
- Create: `src/test/resources/application.yml`
- Modify: `docker-compose.yml`
- Test: `src/test/java/br/com/fiap/hackaton/auth/security/PepperedPasswordEncoderTest.java`

**Interfaces:**
- Consumes: nada de tasks anteriores desta feature — só a `PasswordEncoder` (interface do Spring Security).
- Produces: `PepperedPasswordEncoder implements PasswordEncoder` com construtor `PepperedPasswordEncoder(PasswordEncoder delegate, String pepper)`; bean Spring `PasswordEncoder passwordEncoder(...)` já peppered, pronto para a Task 2 injetar via `@Autowired`.

- [ ] **Step 1: Escrever o teste unitário que falha**

Criar `src/test/java/br/com/fiap/hackaton/auth/security/PepperedPasswordEncoderTest.java`:

```java
package br.com.fiap.hackaton.auth.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

class PepperedPasswordEncoderTest {

  @Test
  void matchesRoundTripsThroughPepperAndArgon2id() {
    PepperedPasswordEncoder encoder =
        new PepperedPasswordEncoder(
            Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(), "test-pepper-value");

    String hash = encoder.encode("MinhaSenh@123");

    assertThat(hash).startsWith("$argon2id$");
    assertThat(hash).isNotEqualTo("MinhaSenh@123");
    assertThat(encoder.matches("MinhaSenh@123", hash)).isTrue();
    assertThat(encoder.matches("SenhaErrada", hash)).isFalse();
  }

  @Test
  void differentPeppersProduceNonMatchingHashesForTheSamePassword() {
    Argon2PasswordEncoder argon2 = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    PepperedPasswordEncoder encoderWithPepperA =
        new PepperedPasswordEncoder(argon2, "pepper-a-secret");
    PepperedPasswordEncoder encoderWithPepperB =
        new PepperedPasswordEncoder(argon2, "pepper-b-secret");

    String hash = encoderWithPepperA.encode("MesmaSenha123");

    assertThat(encoderWithPepperB.matches("MesmaSenha123", hash)).isFalse();
  }
}
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `./mvnw test -Dtest=PepperedPasswordEncoderTest`
Expected: FAIL — compilação quebra (`PepperedPasswordEncoder` ainda não existe; `Argon2PasswordEncoder` ainda não está no classpath).

- [ ] **Step 3: Adicionar as dependências `spring-security-crypto` e `bcprov-jdk18on` ao `pom.xml`**

Dentro de `<dependencies>`, logo após o bloco `<!-- Persistence -->` (dependências adicionadas na AUTH-1: `spring-boot-starter-data-jpa`, `postgresql`, `flyway-core`, `flyway-database-postgresql`) e antes do bloco `<!-- JWT -->`, adicionar:

```xml
        <!-- Password hashing (Argon2id + Pepper) -->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-crypto</artifactId>
        </dependency>
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcprov-jdk18on</artifactId>
        </dependency>
```

`bcprov-jdk18on` é dependência opcional do `spring-security-crypto` — sem ela, `Argon2PasswordEncoder` lança `NoClassDefFoundError` em runtime na primeira chamada a `encode`/`matches`. Se o build acusar que a versão não é gerenciada pelo BOM do `spring-boot-starter-parent`, pinar a versão mais recente estável disponível no Maven Central e anotar isso como desvio no relatório da task.

- [ ] **Step 4: Criar `PepperedPasswordEncoder`**

Criar `src/main/java/br/com/fiap/hackaton/auth/security/PepperedPasswordEncoder.java`:

```java
package br.com.fiap.hackaton.auth.security;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.security.crypto.password.PasswordEncoder;

public class PepperedPasswordEncoder implements PasswordEncoder {

  private static final String HMAC_ALGORITHM = "HmacSHA256";

  private final PasswordEncoder delegate;
  private final SecretKeySpec pepperKey;

  public PepperedPasswordEncoder(PasswordEncoder delegate, String pepper) {
    this.delegate = delegate;
    this.pepperKey = new SecretKeySpec(pepper.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
  }

  @Override
  public String encode(CharSequence rawPassword) {
    return delegate.encode(applyPepper(rawPassword));
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    return delegate.matches(applyPepper(rawPassword), encodedPassword);
  }

  private String applyPepper(CharSequence rawPassword) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(pepperKey);
      byte[] hmac = mac.doFinal(rawPassword.toString().getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(hmac);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Unable to apply password pepper", e);
    }
  }
}
```

- [ ] **Step 5: Rodar o teste e confirmar que passa**

Run: `./mvnw test -Dtest=PepperedPasswordEncoderTest`
Expected: PASS — `matchesRoundTripsThroughPepperAndArgon2id` e `differentPeppersProduceNonMatchingHashesForTheSamePassword` passam.

- [ ] **Step 6: Criar `PasswordEncoderConfig`**

Criar `src/main/java/br/com/fiap/hackaton/auth/config/PasswordEncoderConfig.java`:

```java
package br.com.fiap.hackaton.auth.config;

import br.com.fiap.hackaton.auth.security.PepperedPasswordEncoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordEncoderConfig {

  @Bean
  public PasswordEncoder passwordEncoder(
      @Value("${app.security.password-pepper}") String pepper) {
    return new PepperedPasswordEncoder(
        Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(), pepper);
  }
}
```

- [ ] **Step 7: Adicionar a propriedade do pepper ao `application.yml` (sem default)**

Em `src/main/resources/application.yml`, adicionar ao final (mesmo nível de `server`, `spring`, `management`):

```yaml
app:
  security:
    password-pepper: ${PASSWORD_PEPPER}
```

Sem valor de fallback (`${PASSWORD_PEPPER:algumDefault}`) — se a variável de ambiente não existir, o Spring falha ao subir o contexto com `Could not resolve placeholder 'PASSWORD_PEPPER'`, o que é o comportamento desejado (fail-fast).

- [ ] **Step 8: Criar o pepper de teste em `src/test/resources/application.yml`**

Criar `src/test/resources/application.yml` (arquivo novo — `src/test/resources` ainda não existe no projeto):

```yaml
app:
  security:
    password-pepper: test-only-pepper-do-not-use-in-production
```

O Spring Boot sobrepõe automaticamente `src/test/resources/application.yml` ao `src/main/resources/application.yml` durante os testes, então nenhum teste `@SpringBootTest` existente (AUTH-1) precisa ser alterado para continuar subindo o contexto.

- [ ] **Step 9: Adicionar `PASSWORD_PEPPER` ao `docker-compose.yml` (desenvolvimento local)**

Em `docker-compose.yml`, no bloco `environment` do serviço `auth-service`, adicionar a linha (após as variáveis `DB_*` já existentes):

```yaml
      - PASSWORD_PEPPER=local-dev-pepper-change-me
```

- [ ] **Step 10: Rodar a suíte completa e confirmar que nada quebrou**

Run: `./mvnw test`
Expected: PASS — `PepperedPasswordEncoderTest` (novo) e todos os testes da AUTH-1 (`AuthServiceApplicationTests`, `FlywayMigrationTest`, `UserRepositoryTest`, `FlywayRestartTest`) continuam passando, agora com o contexto Spring subindo com o bean `PasswordEncoder` peppered presente.

- [ ] **Step 11: Commit**

```bash
git add pom.xml src/main/java/br/com/fiap/hackaton/auth/security/PepperedPasswordEncoder.java src/main/java/br/com/fiap/hackaton/auth/config/PasswordEncoderConfig.java src/main/resources/application.yml src/test/resources/application.yml docker-compose.yml src/test/java/br/com/fiap/hackaton/auth/security/PepperedPasswordEncoderTest.java
git commit -m "feat(auth-2): add Argon2id password encoder peppered via HMAC-SHA256"
```

---

### Task 2: Serviço de registro — hash e detecção de e-mail duplicado

**Files:**
- Create: `src/main/java/br/com/fiap/hackaton/auth/user/RegisterRequest.java`
- Create: `src/main/java/br/com/fiap/hackaton/auth/user/EmailAlreadyRegisteredException.java`
- Create: `src/main/java/br/com/fiap/hackaton/auth/user/UserRegistrationService.java`
- Test: `src/test/java/br/com/fiap/hackaton/auth/user/UserRegistrationServiceTest.java`

**Interfaces:**
- Consumes: `User(String name, String email, String passwordHash, UserRole role)` e `UserRepository extends JpaRepository<User, UUID>` (AUTH-1, já commitados); constraint única `uk_users_email` na tabela `users`; bean `PasswordEncoder` peppered (Task 1) — injetado via Spring, o código desta task não sabe que existe pepper por trás.
- Produces: `record RegisterRequest(String name, String email, String password)` com validação Bean Validation; `EmailAlreadyRegisteredException extends RuntimeException`; `UserRegistrationService.register(RegisterRequest): User` — usado pela Task 3.

- [ ] **Step 1: Escrever o teste de serviço que falha**

Criar `src/test/java/br/com/fiap/hackaton/auth/user/UserRegistrationServiceTest.java`:

```java
package br.com.fiap.hackaton.auth.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest
class UserRegistrationServiceTest {

  @Container
  @ServiceConnection
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

  @Autowired private UserRegistrationService userRegistrationService;
  @Autowired private PasswordEncoder passwordEncoder;

  @Test
  void registersUserWithHashedPasswordAndDefaultUserRole() {
    RegisterRequest request =
        new RegisterRequest("Fernanda Reis", "fernanda.service@example.com", "MinhaSenh@123");

    User savedUser = userRegistrationService.register(request);

    assertThat(savedUser.getId()).isNotNull();
    assertThat(savedUser.getRole()).isEqualTo(UserRole.USER);
    assertThat(savedUser.getPasswordHash()).isNotEqualTo("MinhaSenh@123");
    assertThat(savedUser.getPasswordHash()).startsWith("$argon2id$");
    assertThat(passwordEncoder.matches("MinhaSenh@123", savedUser.getPasswordHash())).isTrue();
  }

  @Test
  void throwsEmailAlreadyRegisteredExceptionOnDuplicateEmail() {
    String email = "duplicado.service@example.com";
    userRegistrationService.register(
        new RegisterRequest("Gustavo Prado", email, "PrimeiraSenha1"));

    RegisterRequest duplicate = new RegisterRequest("Helena Dias", email, "SegundaSenha2");

    assertThatThrownBy(() -> userRegistrationService.register(duplicate))
        .isInstanceOf(EmailAlreadyRegisteredException.class)
        .hasMessageContaining(email);
  }
}
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `./mvnw test -Dtest=UserRegistrationServiceTest`
Expected: FAIL — compilação quebra (`RegisterRequest`, `EmailAlreadyRegisteredException`, `UserRegistrationService` ainda não existem).

- [ ] **Step 3: Criar `RegisterRequest`**

Criar `src/main/java/br/com/fiap/hackaton/auth/user/RegisterRequest.java`:

```java
package br.com.fiap.hackaton.auth.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
    @NotBlank(message = "name is required") String name,
    @NotBlank(message = "email is required")
        @Email(message = "email must be a valid email address")
        String email,
    @NotBlank(message = "password is required")
        @Size(min = 8, message = "password must be at least 8 characters")
        String password) {

  @Override
  public String toString() {
    return "RegisterRequest[name=" + name + ", email=" + email + ", password=***]";
  }
}
```

- [ ] **Step 4: Criar `EmailAlreadyRegisteredException`**

Criar `src/main/java/br/com/fiap/hackaton/auth/user/EmailAlreadyRegisteredException.java`:

```java
package br.com.fiap.hackaton.auth.user;

public class EmailAlreadyRegisteredException extends RuntimeException {

  public EmailAlreadyRegisteredException(String email) {
    super("E-mail already registered: " + email);
  }
}
```

- [ ] **Step 5: Criar `UserRegistrationService`**

Criar `src/main/java/br/com/fiap/hackaton/auth/user/UserRegistrationService.java`:

```java
package br.com.fiap.hackaton.auth.user;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserRegistrationService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  public UserRegistrationService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
  }

  public User register(RegisterRequest request) {
    String passwordHash = passwordEncoder.encode(request.password());
    User user = new User(request.name(), request.email(), passwordHash, UserRole.USER);

    try {
      return userRepository.saveAndFlush(user);
    } catch (DataIntegrityViolationException ex) {
      throw new EmailAlreadyRegisteredException(request.email());
    }
  }
}
```

- [ ] **Step 6: Rodar o teste e confirmar que passa**

Run: `./mvnw test -Dtest=UserRegistrationServiceTest`
Expected: PASS — `registersUserWithHashedPasswordAndDefaultUserRole` e `throwsEmailAlreadyRegisteredExceptionOnDuplicateEmail` passam.

- [ ] **Step 7: Commit**

```bash
git add src/main/java/br/com/fiap/hackaton/auth/user/RegisterRequest.java src/main/java/br/com/fiap/hackaton/auth/user/EmailAlreadyRegisteredException.java src/main/java/br/com/fiap/hackaton/auth/user/UserRegistrationService.java src/test/java/br/com/fiap/hackaton/auth/user/UserRegistrationServiceTest.java
git commit -m "feat(auth-2): add registration service with duplicate-email detection"
```

---

### Task 3: Endpoint `POST /auth/register` — validação HTTP, 409/400 e garantia de não vazar a senha

**Files:**
- Create: `src/main/java/br/com/fiap/hackaton/auth/user/UserResponse.java`
- Create: `src/main/java/br/com/fiap/hackaton/auth/user/AuthController.java`
- Create: `src/main/java/br/com/fiap/hackaton/auth/web/ErrorResponse.java`
- Create: `src/main/java/br/com/fiap/hackaton/auth/web/ValidationErrorResponse.java`
- Create: `src/main/java/br/com/fiap/hackaton/auth/web/GlobalExceptionHandler.java`
- Test: `src/test/java/br/com/fiap/hackaton/auth/user/AuthControllerRegisterTest.java`

**Interfaces:**
- Consumes: `UserRegistrationService.register(RegisterRequest): User` e `EmailAlreadyRegisteredException` (Task 2).
- Produces: `POST /auth/register` retornando `201` com `UserResponse(UUID id, String name, String email, UserRole role, Instant createdAt)`; `409` com `ErrorResponse(String message)` em e-mail duplicado; `400` com `ValidationErrorResponse(String message, List<FieldErrorDetail>)` em falha de validação (`FieldErrorDetail(String field, String message)`, sem valor rejeitado).

- [ ] **Step 1: Escrever o teste HTTP que falha**

Criar `src/test/java/br/com/fiap/hackaton/auth/user/AuthControllerRegisterTest.java`:

```java
package br.com.fiap.hackaton.auth.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerRegisterTest {

  @Container
  @ServiceConnection
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository userRepository;
  @Autowired private PasswordEncoder passwordEncoder;

  private ListAppender<ILoggingEvent> logAppender;
  private Logger rootLogger;

  @BeforeEach
  void attachLogAppender() {
    rootLogger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    logAppender = new ListAppender<>();
    logAppender.start();
    rootLogger.addAppender(logAppender);
  }

  @AfterEach
  void detachLogAppender() {
    rootLogger.detachAppender(logAppender);
  }

  @Test
  void registersUserAndStoresHashedPasswordInDatabase() throws Exception {
    String rawPassword = "S3nhaSuperSecreta!";
    String payload =
        """
        {"name":"Ana Silva","email":"ana.registro@example.com","password":"%s"}
        """
            .formatted(rawPassword);

    mockMvc
        .perform(post("/auth/register").contentType("application/json").content(payload))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.id").exists())
        .andExpect(jsonPath("$.name").value("Ana Silva"))
        .andExpect(jsonPath("$.email").value("ana.registro@example.com"))
        .andExpect(jsonPath("$.role").value("USER"))
        .andExpect(jsonPath("$.password").doesNotExist())
        .andExpect(jsonPath("$.passwordHash").doesNotExist());

    User storedUser = userRepository.findByEmail("ana.registro@example.com").orElseThrow();

    assertThat(storedUser.getPasswordHash()).isNotEqualTo(rawPassword);
    assertThat(storedUser.getPasswordHash()).startsWith("$argon2id$");
    assertThat(passwordEncoder.matches(rawPassword, storedUser.getPasswordHash())).isTrue();
  }

  @Test
  void returns409WhenEmailAlreadyRegistered() throws Exception {
    String email = "duplicado.registro@example.com";
    String payload =
        """
        {"name":"Bruno Souza","email":"%s","password":"SenhaValida123"}
        """
            .formatted(email);

    mockMvc
        .perform(post("/auth/register").contentType("application/json").content(payload))
        .andExpect(status().isCreated());

    mockMvc
        .perform(post("/auth/register").contentType("application/json").content(payload))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.message").exists());
  }

  @Test
  void returns400ForInvalidEmailFormat() throws Exception {
    String payload =
        """
        {"name":"Carla Lima","email":"not-an-email","password":"SenhaValida123"}
        """;

    mockMvc
        .perform(post("/auth/register").contentType("application/json").content(payload))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.errors[?(@.field == 'email')]").exists());
  }

  @Test
  void returns400ForPasswordTooShortAndNeverEchoesItBack() throws Exception {
    String shortPassword = "abc123";
    String payload =
        """
        {"name":"Diego Alves","email":"diego.registro@example.com","password":"%s"}
        """
            .formatted(shortPassword);

    var result =
        mockMvc
            .perform(post("/auth/register").contentType("application/json").content(payload))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.errors[?(@.field == 'password')]").exists())
            .andReturn();

    String responseBody = result.getResponse().getContentAsString();
    assertThat(responseBody).doesNotContain(shortPassword);
  }

  @Test
  void neverLogsTheRawPassword() throws Exception {
    String rawPassword = "SenhaQueNuncaDeveApareceNoLog99";
    String payload =
        """
        {"name":"Elis Costa","email":"elis.registro@example.com","password":"%s"}
        """
            .formatted(rawPassword);

    mockMvc
        .perform(post("/auth/register").contentType("application/json").content(payload))
        .andExpect(status().isCreated());

    boolean passwordLeakedToLogs =
        logAppender.list.stream()
            .anyMatch(event -> event.getFormattedMessage().contains(rawPassword));

    assertThat(passwordLeakedToLogs).isFalse();
  }
}
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `./mvnw test -Dtest=AuthControllerRegisterTest`
Expected: FAIL — compilação quebra (`UserResponse`, `AuthController` ainda não existem; sem eles não há rota `/auth/register`).

- [ ] **Step 3: Criar `UserResponse`**

Criar `src/main/java/br/com/fiap/hackaton/auth/user/UserResponse.java`:

```java
package br.com.fiap.hackaton.auth.user;

import java.time.Instant;
import java.util.UUID;

public record UserResponse(UUID id, String name, String email, UserRole role, Instant createdAt) {

  public static UserResponse from(User user) {
    return new UserResponse(
        user.getId(), user.getName(), user.getEmail(), user.getRole(), user.getCreatedAt());
  }
}
```

- [ ] **Step 4: Criar `ErrorResponse` e `ValidationErrorResponse`**

Criar `src/main/java/br/com/fiap/hackaton/auth/web/ErrorResponse.java`:

```java
package br.com.fiap.hackaton.auth.web;

public record ErrorResponse(String message) {}
```

Criar `src/main/java/br/com/fiap/hackaton/auth/web/ValidationErrorResponse.java`:

```java
package br.com.fiap.hackaton.auth.web;

import java.util.List;

public record ValidationErrorResponse(String message, List<FieldErrorDetail> errors) {

  public record FieldErrorDetail(String field, String message) {}
}
```

- [ ] **Step 5: Criar `GlobalExceptionHandler`**

Criar `src/main/java/br/com/fiap/hackaton/auth/web/GlobalExceptionHandler.java`:

```java
package br.com.fiap.hackaton.auth.web;

import br.com.fiap.hackaton.auth.user.EmailAlreadyRegisteredException;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(EmailAlreadyRegisteredException.class)
  public ResponseEntity<ErrorResponse> handleEmailAlreadyRegistered(
      EmailAlreadyRegisteredException ex) {
    return ResponseEntity.status(HttpStatus.CONFLICT).body(new ErrorResponse(ex.getMessage()));
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ValidationErrorResponse> handleValidation(
      MethodArgumentNotValidException ex) {
    List<ValidationErrorResponse.FieldErrorDetail> fieldErrors =
        ex.getBindingResult().getFieldErrors().stream()
            .map(
                error ->
                    new ValidationErrorResponse.FieldErrorDetail(
                        error.getField(), error.getDefaultMessage()))
            .toList();
    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
        .body(new ValidationErrorResponse("Validation failed", fieldErrors));
  }
}
```

- [ ] **Step 6: Criar `AuthController`**

Criar `src/main/java/br/com/fiap/hackaton/auth/user/AuthController.java`:

```java
package br.com.fiap.hackaton.auth.user;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

  private final UserRegistrationService userRegistrationService;

  public AuthController(UserRegistrationService userRegistrationService) {
    this.userRegistrationService = userRegistrationService;
  }

  @PostMapping("/register")
  public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
    User registeredUser = userRegistrationService.register(request);
    return ResponseEntity.status(HttpStatus.CREATED).body(UserResponse.from(registeredUser));
  }
}
```

- [ ] **Step 7: Rodar o teste e confirmar que passa**

Run: `./mvnw test -Dtest=AuthControllerRegisterTest`
Expected: PASS — os 5 testes (`registersUserAndStoresHashedPasswordInDatabase`, `returns409WhenEmailAlreadyRegistered`, `returns400ForInvalidEmailFormat`, `returns400ForPasswordTooShortAndNeverEchoesItBack`, `neverLogsTheRawPassword`) passam.

- [ ] **Step 8: Rodar a suíte completa**

Run: `./mvnw test`
Expected: PASS — todos os testes (AUTH-1: `AuthServiceApplicationTests`, `FlywayMigrationTest`, `UserRepositoryTest`, `FlywayRestartTest`; AUTH-2: `PepperedPasswordEncoderTest`, `UserRegistrationServiceTest`, `AuthControllerRegisterTest`) passam.

- [ ] **Step 9: Commit**

```bash
git add src/main/java/br/com/fiap/hackaton/auth/user/UserResponse.java src/main/java/br/com/fiap/hackaton/auth/user/AuthController.java src/main/java/br/com/fiap/hackaton/auth/web src/test/java/br/com/fiap/hackaton/auth/user/AuthControllerRegisterTest.java
git commit -m "feat(auth-2): add POST /auth/register endpoint with 409/400 handling"
```
