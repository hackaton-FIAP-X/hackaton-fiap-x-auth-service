# AUTH-1: Entidade User e Migration Flyway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Criar a tabela `users` via migration Flyway e a entidade JPA `User` correspondente, provando que a migration roda limpa em base vazia e que reiniciar a aplicação não reaplica nem quebra a migration.

**Architecture:** Adiciona Postgres + Flyway + Spring Data JPA ao `auth-service`. O schema é dono do Flyway (uma migration versionada `V1__create_users_table.sql`); a entidade `User` mapeia essa tabela com `hibernate.ddl-auto=validate` (nunca gera DDL). Testes de integração usam Testcontainers com Postgres real para validar migration, mapeamento e idempotência de restart — sem depender de H2, que diverge do dialeto Postgres usado em produção.

**Tech Stack:** Spring Boot 3.3.4, Spring Data JPA, Flyway, PostgreSQL (driver + Testcontainers), Java 21.

**Spec:** ClickUp AUTH-1 — https://app.clickup.com/t/86e2w9zw7

## Global Constraints

- Tabela `users` com colunas: `id` (uuid, PK), `name`, `email` (unique), `password_hash`, `role`, `created_at` — nomes e semântica exatos do ticket AUTH-1.
- A migration deve rodar limpa em base vazia (sem erros, sem intervenção manual).
- Reiniciar a aplicação não pode reaplicar a migration nem quebrar (Flyway deve reconhecer a versão já aplicada e validar o checksum).
- Pacote raiz do projeto: `br.com.fiap.hackaton.auth` (já existente).
- Java 21 / Spring Boot 3.3.4 (já fixado no `pom.xml`, não alterar).
- Dependências de banco/Flyway/Testcontainers usam as versões gerenciadas pelo BOM `spring-boot-starter-parent` — não fixar versão explícita (padrão já seguido pelas dependências existentes, exceto JJWT que não é gerenciado pelo BOM).

---

## File Structure

- `pom.xml` — adiciona `spring-boot-starter-data-jpa`, `flyway-core`, `flyway-database-postgresql`, driver `postgresql` (runtime), e para testes `spring-boot-testcontainers`, `testcontainers-junit-jupiter`, `testcontainers-postgresql`.
- `docker-compose.yml` — adiciona serviço `postgres` (Postgres 16) para desenvolvimento local; `auth-service` passa a depender dele e recebe as variáveis de conexão.
- `src/main/resources/application.yml` — configura `spring.datasource.*`, `spring.jpa.hibernate.ddl-auto=validate`, `spring.flyway.enabled=true`.
- `src/main/resources/db/migration/V1__create_users_table.sql` — migration que cria a tabela `users`.
- `src/main/java/br/com/fiap/hackaton/auth/user/UserRole.java` — enum de papéis do usuário.
- `src/main/java/br/com/fiap/hackaton/auth/user/User.java` — entidade JPA mapeando `users`.
- `src/main/java/br/com/fiap/hackaton/auth/user/UserRepository.java` — repositório Spring Data.
- `src/test/java/br/com/fiap/hackaton/auth/FlywayMigrationTest.java` — prova que a migration roda limpa em base vazia e cria as colunas esperadas.
- `src/test/java/br/com/fiap/hackaton/auth/FlywayRestartTest.java` — prova que rodar a migration duas vezes (simulando restart) não reaplica nem quebra.
- `src/test/java/br/com/fiap/hackaton/auth/user/UserRepositoryTest.java` — prova o mapeamento da entidade e a constraint de e-mail único.

---

### Task 1: Infraestrutura de banco (Postgres + Flyway) e migration da tabela `users`

**Files:**
- Modify: `pom.xml`
- Modify: `docker-compose.yml`
- Modify: `src/main/resources/application.yml`
- Create: `src/main/resources/db/migration/V1__create_users_table.sql`
- Test: `src/test/java/br/com/fiap/hackaton/auth/FlywayMigrationTest.java`

**Interfaces:**
- Consumes: nada (base do projeto).
- Produces: tabela `users` (colunas `id uuid PK`, `name`, `email` unique, `password_hash`, `role`, `created_at`); propriedades `spring.datasource.url/username/password` configuráveis via env vars `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`; serviço `postgres` do docker-compose acessível em `localhost:5432` com banco/usuário/senha `auth_service`.

- [ ] **Step 1: Escrever o teste de integração que falha (sem dependências/migration ainda)**

Criar `src/test/java/br/com/fiap/hackaton/auth/FlywayMigrationTest.java`:

```java
package br.com.fiap.hackaton.auth;

import static org.assertj.core.api.Assertions.assertThat;

import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest
class FlywayMigrationTest {

  @Container
  @ServiceConnection
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

  @Autowired private Flyway flyway;
  @Autowired private DataSource dataSource;

  @Test
  void migrationAppliesCleanlyOnEmptyDatabase() {
    MigrationInfo current = flyway.info().current();

    assertThat(current).isNotNull();
    assertThat(current.getVersion().getVersion()).isEqualTo("1");
    assertThat(current.getState().isApplied()).isTrue();
  }

  @Test
  void usersTableHasExpectedColumns() {
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);

    var columns =
        jdbcTemplate.queryForList(
            "select column_name from information_schema.columns where table_name = 'users'",
            String.class);

    assertThat(columns)
        .containsExactlyInAnyOrder("id", "name", "email", "password_hash", "role", "created_at");
  }
}
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `./mvnw test -Dtest=FlywayMigrationTest`
Expected: FAIL — compilação quebra (símbolos `Flyway`, `ServiceConnection`, `PostgreSQLContainer` inexistentes) ou, após adicionar dependências, falha por não existir a tabela `users`.

- [ ] **Step 3: Adicionar dependências de banco/Flyway/Testcontainers ao `pom.xml`**

Dentro de `<dependencies>`, logo após o bloco `<!-- JWT -->` existente (antes do bloco `<!-- DevTools for hot reload -->`), adicionar:

```xml
        <!-- Persistence -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.flywaydb</groupId>
            <artifactId>flyway-core</artifactId>
        </dependency>
        <dependency>
            <groupId>org.flywaydb</groupId>
            <artifactId>flyway-database-postgresql</artifactId>
        </dependency>
```

E dentro do bloco `<!-- Test -->` existente, após `spring-boot-starter-test`, adicionar:

```xml
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-testcontainers</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.testcontainers</groupId>
            <artifactId>junit-jupiter</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.testcontainers</groupId>
            <artifactId>postgresql</artifactId>
            <scope>test</scope>
        </dependency>
```

- [ ] **Step 4: Configurar datasource, JPA e Flyway em `application.yml`**

Substituir o conteúdo de `src/main/resources/application.yml` por:

```yaml
server:
  port: 8080

spring:
  application:
    name: auth-service
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

management:
  endpoints:
    web:
      exposure:
        include: health,info,prometheus
  endpoint:
    health:
      show-details: always
  metrics:
    tags:
      application: ${spring.application.name}
```

- [ ] **Step 5: Criar a migration `V1__create_users_table.sql`**

Criar `src/main/resources/db/migration/V1__create_users_table.sql`:

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT uk_users_email UNIQUE (email)
);
```

- [ ] **Step 6: Rodar o teste e confirmar que passa**

Run: `./mvnw test -Dtest=FlywayMigrationTest`
Expected: PASS — os dois testes (`migrationAppliesCleanlyOnEmptyDatabase`, `usersTableHasExpectedColumns`) passam contra o Postgres do Testcontainers.

- [ ] **Step 7: Adicionar o serviço `postgres` ao `docker-compose.yml` para desenvolvimento local**

Substituir o conteúdo de `docker-compose.yml` por:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    container_name: auth-service-postgres
    environment:
      - POSTGRES_DB=auth_service
      - POSTGRES_USER=auth_service
      - POSTGRES_PASSWORD=auth_service
    ports:
      - "5432:5432"
    volumes:
      - auth_service_postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U auth_service -d auth_service"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  auth-service:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: auth-service
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
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped

volumes:
  auth_service_postgres_data:
```

- [ ] **Step 8: Commit**

```bash
git add pom.xml docker-compose.yml src/main/resources/application.yml src/main/resources/db/migration/V1__create_users_table.sql src/test/java/br/com/fiap/hackaton/auth/FlywayMigrationTest.java
git commit -m "feat(auth-1): add postgres/flyway infra and users table migration"
```

---

### Task 2: Entidade `User` e `UserRepository`

**Files:**
- Create: `src/main/java/br/com/fiap/hackaton/auth/user/UserRole.java`
- Create: `src/main/java/br/com/fiap/hackaton/auth/user/User.java`
- Create: `src/main/java/br/com/fiap/hackaton/auth/user/UserRepository.java`
- Test: `src/test/java/br/com/fiap/hackaton/auth/user/UserRepositoryTest.java`

**Interfaces:**
- Consumes: tabela `users` criada na Task 1 (`V1__create_users_table.sql`).
- Produces: `User(String name, String email, String passwordHash, UserRole role)`; getters `getId():UUID`, `getName():String`, `getEmail():String`, `getPasswordHash():String`, `getRole():UserRole`, `getCreatedAt():Instant`; enum `UserRole { ADMIN, USER }`; `UserRepository extends JpaRepository<User, UUID>` com `findByEmail(String):Optional<User>`.

- [ ] **Step 1: Escrever o teste de repositório que falha**

Criar `src/test/java/br/com/fiap/hackaton/auth/user/UserRepositoryTest.java`:

```java
package br.com.fiap.hackaton.auth.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.dao.DataIntegrityViolationException;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest
class UserRepositoryTest {

  @Container
  @ServiceConnection
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

  @Autowired private UserRepository userRepository;

  @Test
  void savesAndReadsUserBackByEmail() {
    User user = new User("Ana Silva", "ana.silva@example.com", "hashed-password", UserRole.USER);

    userRepository.saveAndFlush(user);

    var found = userRepository.findByEmail("ana.silva@example.com");

    assertThat(found).isPresent();
    assertThat(found.get().getId()).isNotNull();
    assertThat(found.get().getName()).isEqualTo("Ana Silva");
    assertThat(found.get().getRole()).isEqualTo(UserRole.USER);
    assertThat(found.get().getCreatedAt()).isNotNull();
  }

  @Test
  void rejectsDuplicateEmail() {
    userRepository.saveAndFlush(
        new User("Bruno Souza", "duplicado@example.com", "hash-1", UserRole.USER));

    User duplicate = new User("Carla Lima", "duplicado@example.com", "hash-2", UserRole.ADMIN);

    assertThrows(
        DataIntegrityViolationException.class, () -> userRepository.saveAndFlush(duplicate));
  }
}
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `./mvnw test -Dtest=UserRepositoryTest`
Expected: FAIL — compilação quebra (`User`, `UserRole`, `UserRepository` ainda não existem).

- [ ] **Step 3: Criar o enum `UserRole`**

Criar `src/main/java/br/com/fiap/hackaton/auth/user/UserRole.java`:

```java
package br.com.fiap.hackaton.auth.user;

public enum UserRole {
  ADMIN,
  USER
}
```

- [ ] **Step 4: Criar a entidade `User`**

Criar `src/main/java/br/com/fiap/hackaton/auth/user/User.java`:

```java
package br.com.fiap.hackaton.auth.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.UuidGenerator;

@Entity
@Table(name = "users")
public class User {

  @Id
  @UuidGenerator
  @Column(columnDefinition = "uuid", updatable = false, nullable = false)
  private UUID id;

  @Column(nullable = false)
  private String name;

  @Column(nullable = false, unique = true)
  private String email;

  @Column(name = "password_hash", nullable = false)
  private String passwordHash;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private UserRole role;

  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  protected User() {}

  public User(String name, String email, String passwordHash, UserRole role) {
    this.name = name;
    this.email = email;
    this.passwordHash = passwordHash;
    this.role = role;
  }

  @PrePersist
  void onCreate() {
    if (createdAt == null) {
      createdAt = Instant.now();
    }
  }

  public UUID getId() {
    return id;
  }

  public String getName() {
    return name;
  }

  public String getEmail() {
    return email;
  }

  public String getPasswordHash() {
    return passwordHash;
  }

  public UserRole getRole() {
    return role;
  }

  public Instant getCreatedAt() {
    return createdAt;
  }
}
```

- [ ] **Step 5: Criar o `UserRepository`**

Criar `src/main/java/br/com/fiap/hackaton/auth/user/UserRepository.java`:

```java
package br.com.fiap.hackaton.auth.user;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, UUID> {

  Optional<User> findByEmail(String email);
}
```

- [ ] **Step 6: Rodar o teste e confirmar que passa**

Run: `./mvnw test -Dtest=UserRepositoryTest`
Expected: PASS — `savesAndReadsUserBackByEmail` e `rejectsDuplicateEmail` passam.

- [ ] **Step 7: Commit**

```bash
git add src/main/java/br/com/fiap/hackaton/auth/user src/test/java/br/com/fiap/hackaton/auth/user
git commit -m "feat(auth-1): add User entity and UserRepository"
```

---

### Task 3: Provar que restart não reaplica nem quebra a migration

**Files:**
- Test: `src/test/java/br/com/fiap/hackaton/auth/FlywayRestartTest.java`

**Interfaces:**
- Consumes: migration `V1__create_users_table.sql` (Task 1).
- Produces: nada além da prova em si (teste de verificação, sem novo código de produção).

- [ ] **Step 1: Escrever o teste que simula dois boots consecutivos contra o mesmo banco**

Criar `src/test/java/br/com/fiap/hackaton/auth/FlywayRestartTest.java`:

```java
package br.com.fiap.hackaton.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.output.MigrateResult;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
class FlywayRestartTest {

  @Container static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

  private Flyway flywayPointingAtContainer() {
    return Flyway.configure()
        .dataSource(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword())
        .load();
  }

  @Test
  void restartingApplicationDoesNotReapplyOrBreakMigration() {
    MigrateResult firstBoot = flywayPointingAtContainer().migrate();
    assertThat(firstBoot.migrationsExecuted).isEqualTo(1);

    MigrateResult secondBoot = flywayPointingAtContainer().migrate();
    assertThat(secondBoot.migrationsExecuted).isEqualTo(0);

    assertThatCode(() -> flywayPointingAtContainer().validate()).doesNotThrowAnyException();
  }
}
```

- [ ] **Step 2: Rodar o teste**

Run: `./mvnw test -Dtest=FlywayRestartTest`
Expected: PASS — primeira execução aplica 1 migration, a segunda aplica 0 (já registrada no `flyway_schema_history`), e `validate()` não lança exceção (checksum íntegro).

- [ ] **Step 3: Rodar a suíte completa**

Run: `./mvnw test`
Expected: PASS — todos os testes (`AuthServiceApplicationTests`, `FlywayMigrationTest`, `UserRepositoryTest`, `FlywayRestartTest`) passam.

- [ ] **Step 4: Commit**

```bash
git add src/test/java/br/com/fiap/hackaton/auth/FlywayRestartTest.java
git commit -m "test(auth-1): prove flyway migration survives application restart"
```
