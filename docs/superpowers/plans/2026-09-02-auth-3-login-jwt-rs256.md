# AUTH-3: Login com Emissão de JWT RS256 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implementar `POST /auth/login` no auth-service: recebe e-mail/senha, verifica contra o hash Argon2id+Pepper (AUTH-2), e emite um JWT assinado com RS256 (par de chaves RSA lido de variáveis de ambiente, nunca commitado) contendo os claims `sub`, `email`, `name`, `iss=fiapx-auth` e expiração de 15 minutos. Credencial inválida — e-mail inexistente ou senha errada — retorna sempre o mesmo 401 genérico, sem revelar qual dos dois casos ocorreu.

**Architecture:** `JwtKeyConfig` carrega o par de chaves RSA (base64 de DER, PKCS8 para a privada e X509 para a pública) das variáveis de ambiente e expõe `PrivateKey`/`PublicKey` como beans Spring — sem default em produção (fail-fast), mesmo padrão já usado para o pepper na AUTH-2. `JwtTokenService` (pacote `security`, ao lado de `PepperedPasswordEncoder`) usa a `PrivateKey` para assinar tokens via a biblioteca JJWT (já presente no `pom.xml` desde o esqueleto inicial do projeto — nenhuma dependência nova). `AuthenticationService` (pacote `user`, ao lado de `UserRegistrationService`) orquestra o login: busca o usuário por e-mail normalizado, verifica a senha via `PasswordEncoder` (a mesma implementação peppered da AUTH-2, injetada apenas pela interface), e — quando o e-mail não existe — ainda assim executa uma verificação de senha contra um hash "isca" pré-computado, para que o tempo de resposta não seja um canal lateral que revele se o e-mail está cadastrado (Argon2id é deliberadamente lento, então pular essa etapa quando o usuário não existe criaria uma diferença de tempo facilmente observável). `AuthController` (já existente, criado na AUTH-2) ganha o método `login`, reaproveitando o `ErrorResponse` da AUTH-2 para o corpo do 401 — sem novo DTO de erro. A proteção contra vazamento de senha em log via `spring.mvc.log-resolved-exception` (corrigida na revisão final da AUTH-2) já é configuração global da aplicação, então cobre `/auth/login` automaticamente, sem precisar de um teste de log duplicado por endpoint.

**Tech Stack:** Spring Boot 3.3.4, JJWT 0.12.3 (`jjwt-api`/`jjwt-impl`/`jjwt-jackson`, já no `pom.xml`), `java.security` puro para carregar as chaves RSA (sem dependência nova), Spring Data JPA + `PasswordEncoder` peppered (AUTH-1/AUTH-2), Java 21, Postgres via Testcontainers para os testes.

**Spec:** ClickUp AUTH-3 — https://app.clickup.com/t/86e2w9zwa

## Global Constraints

- Endpoint: `POST /auth/login`.
- **RS256** — par de chaves RSA lido de variáveis de ambiente `JWT_PRIVATE_KEY` (base64 de DER PKCS8) e `JWT_PUBLIC_KEY` (base64 de DER X509), **nunca commitado**. Sem default em `src/main/resources/application.yml` — a aplicação falha ao subir se ausente (fail-fast), mesmo padrão do `PASSWORD_PEPPER` na AUTH-2. Formato base64-de-DER (não PEM multi-linha) evita problemas de quebra de linha em variáveis de ambiente/docker-compose/Secrets.
- Claims do token: `sub` = `user.getId()` (UUID como string), `email`, `name`, `iss` = `"fiapx-auth"` (valor fixo definido pelo ticket — não configurável via propriedade, é uma constante no código), `iat` = agora, `exp` = `iat` + **15 minutos**.
- Credencial inválida (e-mail não encontrado OU senha incorreta) retorna **401 Unauthorized** com o mesmo corpo genérico `ErrorResponse{message: "Invalid credentials"}` nos dois casos — nunca revela qual dos dois motivos ocorreu, nem no corpo nem em `MethodArgumentNotValidException` (protegido globalmente desde a AUTH-2).
- **Mitigação de canal lateral por tempo**: mesmo quando o e-mail não existe, `AuthenticationService` executa `passwordEncoder.matches(...)` contra um hash "isca" pré-computado (mesmo encoder peppered, calculado uma vez na construção do bean) — evita que a ausência de uma chamada Argon2id (deliberadamente lenta) vaze, por tempo de resposta, que o e-mail não está cadastrado. Vai além do texto literal do ticket, mas decorre diretamente do critério "sem revelar se o e-mail existe".
- `LoginRequest` valida apenas `@NotBlank` em `email`/`password` — deliberadamente **sem** `@Email`/`@Size`, para não introduzir um código de status diferente (400 vs 401) que funcione como canal lateral adicional revelando algo sobre o formato esperado; toda credencial que não bate cai no mesmo caminho 401 genérico. `toString()` redige a senha, mesmo padrão do `RegisterRequest` (AUTH-2).
- Reaproveita `br.com.fiap.hackaton.auth.web.ErrorResponse` (já existente, AUTH-2) para o corpo do 401 — não cria um novo DTO de erro.
- "Token válida no jwt.io com a chave pública" é provado de forma automatizada: os testes parseiam e verificam a assinatura do token com o parser da própria JJWT usando a `PublicKey` bean (`Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(token)`) — equivalente ao que o jwt.io faz no lado do cliente. Uma conferência manual real no jwt.io fica a critério do usuário como checagem adicional, não faz parte da suíte automatizada.
- Pacotes: `JwtKeyConfig` em `br.com.fiap.hackaton.auth.config` (wiring); `JwtTokenService` em `br.com.fiap.hackaton.auth.security` (primitivo de criptografia, ao lado de `PepperedPasswordEncoder`); `LoginRequest`, `LoginResponse`, `InvalidCredentialsException`, `AuthenticationService` em `br.com.fiap.hackaton.auth.user` (mesmo pacote de `RegisterRequest`/`UserRegistrationService`); `AuthController` e `GlobalExceptionHandler` são os mesmos arquivos já existentes da AUTH-2, modificados in-place (não duplicados).
- Java 21 / Spring Boot 3.3.4 (não alterar). **Nenhuma dependência nova** — `jjwt-api`/`jjwt-impl`/`jjwt-jackson` 0.12.3 já estão no `pom.xml` desde o esqueleto inicial do projeto; carregar as chaves RSA usa apenas `java.security.KeyFactory` puro do JDK.
- Chave de teste fixa (par RSA gerado uma única vez, injetado via Surefire `systemPropertyVariables` no `pom.xml`, mesmo padrão do `PASSWORD_PEPPER` de teste da AUTH-2 — **não** um `src/test/resources/application.yml`, que já causou um bug de sombreamento de config corrigido na AUTH-2):
  - `JWT_PRIVATE_KEY` = `MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCosPEdHeTioaJ8EWjDuS3oH+5CpGthPUJZJfBfsSIaHz9zQXUtClhoo8eF5aam1T7SA2XS+DyQoejMOFK6LYifcTsP6tae6WyKXeTrLW6JRKyMuYfRCCie6QU0R1iglDlRnfAfy4E50M5uVdPDda5n+L04c3Rc9pSDCHki3YTMfEkDNroUeJRn9lrB2mwBxjCw+a2a9xVpeSmx5BGHPNrG2/hX1RPl8E2HZnVz+2epXIFYFWZdIl8is+S/OF4xGVEiLPwQor3TWUd3eP2uOzrB8dBCjn9clGa24z7107qfyPcFoAjaru4eKGG8UD6IMP7sR2qmFIDB9upQHIFl+S+HAgMBAAECggEARWn19WTBM+6N9V6WjP9MoBlPifWtR+iUvilJ5Z52aWhVTCBxzpRUt845AmRy9HCINpP2WN8T0PIG4M4GYJzu/KjzxEN+iAqGQtOLKKjbtLlhBVEszXt9d5JsNUxscDs98NM8JWEwrjE5WJaRmnr4xsjIWAvOJJjEmLyqWAnuJNQOkuJ6fS9mmhnbORL9kQ8dn5j03eXEYM1bihcZYYfxxBtq38kuv5k6YSLD3NhEE251oRHRjU5kmR3qu/2f52y6Yn0MAMtIZmaGfa/7u9VjkCdlJ273NrMWhLNfe3BUERVGrYGD6gdZE/fwzw1Vf09YXB1aavpS1dCwK8w9kVWafQKBgQDQcSEEH7pZXr1+cyp5FY1m5MOpRHaPHLrJmpm3fwn/2h10thOIX63twKWTdouMrWfDLitBSRUQoI3+6ML0XUv48HVrRYiTC6PjlYDYCfi4Bd5Jhz5cPWb3soJE5ADMfpTvvoq9R7SpiEeqC39DslA6PL5k+mHv8Pct3verE8mTiwKBgQDPLgPLSi9ftQU5vyl4llBkAgovDEG59aOlE5Fh9RYaY54NqVv8HMdvuctUaWYH751qv9AZkl15phj4Sb8hrke4KlsfrWkSAHtKM82dZERWy90GS1Vj3xBzImCftVr2qPBnOXzNSOlU4IU2d/Kc2+q/nLMEuk4IZuknEQKS5Z5jdQKBgClt8uQA8mcE/6D8fvqmH/7NhV5Fb1MuoKmlgtwH8hLaZXRnJCa87bMN0Vsn+sCxTqhqqspFHly5rL93wBgV2x3VnWD+5xBjBeYcNwm5oafh8ramnOx0f9zHrEDJGKeMmUm1k5nfgLcZkTTpKBhqfqu0mxsy8Phh6p9Ba/Si8DPVAoGBAIGUiC74AVVdBR2vIKMZcMJ8PB5dDibfKjEvYfjgr6hlsg9dY/j1jw+kJzZujbBdABoqSmAUGX7iki+JAJByTs0zQLc5YMQvpO0uJWZRtiSLcXxkVc4XUFSSpdh+N5ya4XHOlO5YsgeyPd9pekb9jX+25IkKdY/vvdf/XZq/HyeZAoGAKbFaSVNFdBbASpZkzJEh/Pa1DU/aInFMQ8TFg0iXXDXPWCyfY/fQqJp58DSfxqH813PtLY9sIFMyYp0KnJ4KC5EtW3vxtjgS7cuwsn44zVcND+Q+NAUxQN5bfIsBXqm3NaBOpPJyG7fmRsRI5PhofMRqatO1qtyddoWpYRty7+0=`
  - `JWT_PUBLIC_KEY` = `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqLDxHR3k4qGifBFow7kt6B/uQqRrYT1CWSXwX7EiGh8/c0F1LQpYaKPHheWmptU+0gNl0vg8kKHozDhSui2In3E7D+rWnulsil3k6y1uiUSsjLmH0QgonukFNEdYoJQ5UZ3wH8uBOdDOblXTw3WuZ/i9OHN0XPaUgwh5It2EzHxJAza6FHiUZ/ZawdpsAcYwsPmtmvcVaXkpseQRhzzaxtv4V9UT5fBNh2Z1c/tnqVyBWBVmXSJfIrPkvzheMRlRIiz8EKK901lHd3j9rjs6wfHQQo5/XJRmtuM+9dO6n8j3BaAI2q7uHihhvFA+iDD+7EdqphSAwfbqUByBZfkvhwIDAQAB`
- Chave de dev local (docker-compose, diferente da de teste — mesmo princípio já seguido para o `PASSWORD_PEPPER` na AUTH-2, valores distintos entre teste e dev):
  - `JWT_PRIVATE_KEY` = `MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC8lw1/LUio9/sSKCJfc2QIYMOlMOf5VTHS0968XrKgQ7fA/IsZIO9v7bph1+iOQMZxKt3DSSd28UKXbp1eNdC9eSPO3XVQdHvTupgt36579dTKgDDEPWV7+C6rNgpJN3qcnF5DAmOzEhPGRv0omI7TBrhZ3fxgMTZIDMyUxgeM65JSGuaE7suol5Q9zOxExxar8krYD082xNyCD0EBOBDyUdxQRl2G66x6C+iaTx2S2w0Q1ZnQQ21obxUX6uOh21huOdf8KhTr2mq6m59+9HuDwX9szSHvg/B6Jx9gym+YQhwuLdJU+w1pMrQlQWZkbzW8I95hswBMnpU2nUCwXelFAgMBAAECggEABqqdnYXvmu7Of0ElReksULzVmFH26/ITsCIxLh4i2QDLzr9JTiVt5q+pS6rNhl8fz1b2k9/9dyTmzQzp9ISZJmQmhzoo2s6N+gQPO7/mc8H9jahOZlbNRD6XrRGx92NGAEyUFcZQg+n7Ak1MHFKYPzluQYRUAYp7zWbhFyPmQcLv03J6RS0r8SDElro065yfw8BEV8/jode3fw3NzUiaoskcjNrPhBPuSCfxGG6n4dHWolQEQjwCHoBOPCPB6L7w+krGL5oyDnni1FRRQzBDX3LHZym6XMExSw+QlZgUD7K0AgTYon7hA28MJedCi0+Ff7Kd1wo8KQDpAeIT6t1wQQKBgQDkWi9o/+dYZl6Zer31kvs/3yqMXJsW7E8l0b/2/QHoHIYVLkuQfvrctfn3MdoJR34QX9BrlIDZkKybnpx1SVL/LnGqEYhZxkS603j0tYjT4B9ozb9y6o3igMdTg4thWlBZCQoWCc0W8wfGDeW6amKthV5FTNyzFp7WWccMIP1zWQKBgQDTbG5IvLX++c0V7Y0fv4yNdS8qQFiCEC+UfqkSIPinnQZrDNVo4+dqdhp/ZpHGhV8lohEyjVsbaUhlrmwwHQ+1kUmQJkL05x6kF459dhReXs86It6pXgCoW0JeMLa7dnAQRT0UQOtrj5Oo9VCSbJjbGrDys3A2BAG7wSoi7DKDzQKBgQCO44QBLwhjf4M4hN6y+Ssw14N3W0dMu8f3AV4evkjgJmEcheCQ5XQygciNjutBnTPcKShw+Pb7rRTlOAXtOlmuBjDn25q3mmJNiaCJd8LL2dWtrflbfjwUfMK9lnW0EGBwpkBic/Wao668ltumn4Vp0SehM6xyf/gaZwkvpMET2QKBgQCpBVFxcvQoYDn1otCkpfTOjfVj2McpS5lOJKgzZwqCrUUZRcxCq5gxAzQRz8UQqUU0h8kp2doRIu0O5Q92s3UAmaLuy7fRpAdZ9b8jS8fi3fbbKk9JpW3vKe338QfU/E2ApGm9DF1owwKwG1YLiSf2WfNGQ++cLz3XhQiTnLKRrQKBgQDRhlWNzP7KKssePEstxOiqBARrafylp2LmVc4LgTgvJhvgfxmckOjDBQb4Zya20Lo19VVyXcBLGC3HexXsYThBCL/bDm0PAfxSz6zgoRwZGeRv0UILHXMYUB9WbGa5fe9ixb6YwKNTH7kOT0/MIv/eAM81kCR9UFzJ0m005rjD9w==`
  - `JWT_PUBLIC_KEY` = `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvJcNfy1IqPf7EigiX3NkCGDDpTDn+VUx0tPevF6yoEO3wPyLGSDvb+26YdfojkDGcSrdw0kndvFCl26dXjXQvXkjzt11UHR707qYLd+ue/XUyoAwxD1le/guqzYKSTd6nJxeQwJjsxITxkb9KJiO0wa4Wd38YDE2SAzMlMYHjOuSUhrmhO7LqJeUPczsRMcWq/JK2A9PNsTcgg9BATgQ8lHcUEZdhuusegvomk8dktsNENWZ0ENtaG8VF+rjodtYbjnX/CoU69pqupuffvR7g8F/bM0h74PweicfYMpvmEIcLi3SVPsNaTK0JUFmZG81vCPeYbMATJ6VNp1AsF3pRQIDAQAB`

---

## File Structure

- `pom.xml` — adiciona `JWT_PRIVATE_KEY`/`JWT_PUBLIC_KEY` ao bloco `systemPropertyVariables` do Surefire (já existente desde a AUTH-2).
- `src/main/resources/application.yml` — adiciona `app.security.jwt.private-key`/`app.security.jwt.public-key` (sem default).
- `docker-compose.yml` — adiciona `JWT_PRIVATE_KEY`/`JWT_PUBLIC_KEY` ao ambiente do serviço `auth-service` (valores de dev).
- `src/main/java/br/com/fiap/hackaton/auth/config/JwtKeyConfig.java` — beans `PrivateKey`/`PublicKey` a partir das variáveis de ambiente.
- `src/main/java/br/com/fiap/hackaton/auth/security/JwtTokenService.java` — `generateToken(User): String`, assina com RS256.
- `src/main/java/br/com/fiap/hackaton/auth/user/LoginRequest.java` — DTO de entrada (`email`, `password`), `toString()` redige a senha.
- `src/main/java/br/com/fiap/hackaton/auth/user/InvalidCredentialsException.java` — exceção de domínio, mensagem fixa "Invalid credentials".
- `src/main/java/br/com/fiap/hackaton/auth/user/AuthenticationService.java` — orquestra o login, com mitigação de timing.
- `src/main/java/br/com/fiap/hackaton/auth/user/LoginResponse.java` — DTO de saída (`token`).
- `src/main/java/br/com/fiap/hackaton/auth/user/AuthController.java` — **modificado**: adiciona `POST /auth/login`.
- `src/main/java/br/com/fiap/hackaton/auth/web/GlobalExceptionHandler.java` — **modificado**: adiciona handler de `InvalidCredentialsException` → 401.
- `src/test/java/br/com/fiap/hackaton/auth/security/JwtTokenServiceTest.java` — prova claims e assinatura RS256 via a `PublicKey` bean.
- `src/test/java/br/com/fiap/hackaton/auth/user/AuthenticationServiceTest.java` — prova login correto, senha errada, e-mail inexistente, e mensagem idêntica nos dois casos de falha.
- `src/test/java/br/com/fiap/hackaton/auth/user/AuthControllerLoginTest.java` — prova o contrato HTTP completo: 200 com token válido (parseado com a chave pública), 401 genérico idêntico para senha errada e e-mail inexistente.

---

### Task 1: Chaves RSA e geração de token JWT (RS256)

**Files:**
- Modify: `pom.xml`
- Modify: `src/main/resources/application.yml`
- Modify: `docker-compose.yml`
- Create: `src/main/java/br/com/fiap/hackaton/auth/config/JwtKeyConfig.java`
- Create: `src/main/java/br/com/fiap/hackaton/auth/security/JwtTokenService.java`
- Test: `src/test/java/br/com/fiap/hackaton/auth/security/JwtTokenServiceTest.java`

**Interfaces:**
- Consumes: `User(String name, String email, String passwordHash, UserRole role)` e `UserRepository extends JpaRepository<User, UUID>` (AUTH-1); JJWT 0.12.3 já presente no `pom.xml`.
- Produces: beans `PrivateKey` e `PublicKey` (Spring, via `JwtKeyConfig`); `JwtTokenService.generateToken(User): String` — usado pela Task 2.

- [ ] **Step 1: Escrever o teste que falha**

Criar `src/test/java/br/com/fiap/hackaton/auth/security/JwtTokenServiceTest.java`:

```java
package br.com.fiap.hackaton.auth.security;

import static org.assertj.core.api.Assertions.assertThat;

import br.com.fiap.hackaton.auth.user.User;
import br.com.fiap.hackaton.auth.user.UserRepository;
import br.com.fiap.hackaton.auth.user.UserRole;
import io.jsonwebtoken.Jwts;
import java.security.PublicKey;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest
class JwtTokenServiceTest {

  @Container
  @ServiceConnection
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

  @Autowired private JwtTokenService jwtTokenService;
  @Autowired private UserRepository userRepository;
  @Autowired private PublicKey jwtPublicKey;

  @Test
  void generatesTokenWithExpectedClaimsSignedWithRs256() {
    User user =
        userRepository.saveAndFlush(
            new User("Fernanda Reis", "fernanda.jwt@example.com", "unused-hash", UserRole.USER));

    String token = jwtTokenService.generateToken(user);

    var claims =
        Jwts.parser().verifyWith(jwtPublicKey).build().parseSignedClaims(token).getPayload();

    assertThat(claims.getSubject()).isEqualTo(user.getId().toString());
    assertThat(claims.get("email", String.class)).isEqualTo("fernanda.jwt@example.com");
    assertThat(claims.get("name", String.class)).isEqualTo("Fernanda Reis");
    assertThat(claims.getIssuer()).isEqualTo("fiapx-auth");

    long expirySeconds =
        (claims.getExpiration().getTime() - claims.getIssuedAt().getTime()) / 1000;
    assertThat(expirySeconds).isEqualTo(15 * 60);
  }
}
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `./mvnw test -Dtest=JwtTokenServiceTest`
Expected: FAIL — compilação quebra (`JwtTokenService` ainda não existe; sem `JwtKeyConfig`, não há bean `PublicKey` para autowire).

- [ ] **Step 3: Adicionar as chaves de teste ao Surefire no `pom.xml`**

No `pom.xml`, dentro do `<plugin>` do `maven-surefire-plugin` já existente (bloco `<!-- Surefire -->`), adicionar as duas novas entradas dentro de `<systemPropertyVariables>`, ao lado de `PASSWORD_PEPPER`:

```xml
                        <JWT_PRIVATE_KEY>MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCosPEdHeTioaJ8EWjDuS3oH+5CpGthPUJZJfBfsSIaHz9zQXUtClhoo8eF5aam1T7SA2XS+DyQoejMOFK6LYifcTsP6tae6WyKXeTrLW6JRKyMuYfRCCie6QU0R1iglDlRnfAfy4E50M5uVdPDda5n+L04c3Rc9pSDCHki3YTMfEkDNroUeJRn9lrB2mwBxjCw+a2a9xVpeSmx5BGHPNrG2/hX1RPl8E2HZnVz+2epXIFYFWZdIl8is+S/OF4xGVEiLPwQor3TWUd3eP2uOzrB8dBCjn9clGa24z7107qfyPcFoAjaru4eKGG8UD6IMP7sR2qmFIDB9upQHIFl+S+HAgMBAAECggEARWn19WTBM+6N9V6WjP9MoBlPifWtR+iUvilJ5Z52aWhVTCBxzpRUt845AmRy9HCINpP2WN8T0PIG4M4GYJzu/KjzxEN+iAqGQtOLKKjbtLlhBVEszXt9d5JsNUxscDs98NM8JWEwrjE5WJaRmnr4xsjIWAvOJJjEmLyqWAnuJNQOkuJ6fS9mmhnbORL9kQ8dn5j03eXEYM1bihcZYYfxxBtq38kuv5k6YSLD3NhEE251oRHRjU5kmR3qu/2f52y6Yn0MAMtIZmaGfa/7u9VjkCdlJ273NrMWhLNfe3BUERVGrYGD6gdZE/fwzw1Vf09YXB1aavpS1dCwK8w9kVWafQKBgQDQcSEEH7pZXr1+cyp5FY1m5MOpRHaPHLrJmpm3fwn/2h10thOIX63twKWTdouMrWfDLitBSRUQoI3+6ML0XUv48HVrRYiTC6PjlYDYCfi4Bd5Jhz5cPWb3soJE5ADMfpTvvoq9R7SpiEeqC39DslA6PL5k+mHv8Pct3verE8mTiwKBgQDPLgPLSi9ftQU5vyl4llBkAgovDEG59aOlE5Fh9RYaY54NqVv8HMdvuctUaWYH751qv9AZkl15phj4Sb8hrke4KlsfrWkSAHtKM82dZERWy90GS1Vj3xBzImCftVr2qPBnOXzNSOlU4IU2d/Kc2+q/nLMEuk4IZuknEQKS5Z5jdQKBgClt8uQA8mcE/6D8fvqmH/7NhV5Fb1MuoKmlgtwH8hLaZXRnJCa87bMN0Vsn+sCxTqhqqspFHly5rL93wBgV2x3VnWD+5xBjBeYcNwm5oafh8ramnOx0f9zHrEDJGKeMmUm1k5nfgLcZkTTpKBhqfqu0mxsy8Phh6p9Ba/Si8DPVAoGBAIGUiC74AVVdBR2vIKMZcMJ8PB5dDibfKjEvYfjgr6hlsg9dY/j1jw+kJzZujbBdABoqSmAUGX7iki+JAJByTs0zQLc5YMQvpO0uJWZRtiSLcXxkVc4XUFSSpdh+N5ya4XHOlO5YsgeyPd9pekb9jX+25IkKdY/vvdf/XZq/HyeZAoGAKbFaSVNFdBbASpZkzJEh/Pa1DU/aInFMQ8TFg0iXXDXPWCyfY/fQqJp58DSfxqH813PtLY9sIFMyYp0KnJ4KC5EtW3vxtjgS7cuwsn44zVcND+Q+NAUxQN5bfIsBXqm3NaBOpPJyG7fmRsRI5PhofMRqatO1qtyddoWpYRty7+0=</JWT_PRIVATE_KEY>
                        <JWT_PUBLIC_KEY>MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqLDxHR3k4qGifBFow7kt6B/uQqRrYT1CWSXwX7EiGh8/c0F1LQpYaKPHheWmptU+0gNl0vg8kKHozDhSui2In3E7D+rWnulsil3k6y1uiUSsjLmH0QgonukFNEdYoJQ5UZ3wH8uBOdDOblXTw3WuZ/i9OHN0XPaUgwh5It2EzHxJAza6FHiUZ/ZawdpsAcYwsPmtmvcVaXkpseQRhzzaxtv4V9UT5fBNh2Z1c/tnqVyBWBVmXSJfIrPkvzheMRlRIiz8EKK901lHd3j9rjs6wfHQQo5/XJRmtuM+9dO6n8j3BaAI2q7uHihhvFA+iDD+7EdqphSAwfbqUByBZfkvhwIDAQAB</JWT_PUBLIC_KEY>
```

- [ ] **Step 4: Criar `JwtKeyConfig`**

Criar `src/main/java/br/com/fiap/hackaton/auth/config/JwtKeyConfig.java`:

```java
package br.com.fiap.hackaton.auth.config;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtKeyConfig {

  @Bean
  public PrivateKey jwtPrivateKey(
      @Value("${app.security.jwt.private-key}") String privateKeyBase64) {
    try {
      byte[] decoded = Base64.getDecoder().decode(privateKeyBase64);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decoded));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new IllegalStateException("Unable to load JWT private key", e);
    }
  }

  @Bean
  public PublicKey jwtPublicKey(@Value("${app.security.jwt.public-key}") String publicKeyBase64) {
    try {
      byte[] decoded = Base64.getDecoder().decode(publicKeyBase64);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return keyFactory.generatePublic(new X509EncodedKeySpec(decoded));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new IllegalStateException("Unable to load JWT public key", e);
    }
  }
}
```

- [ ] **Step 5: Criar `JwtTokenService`**

Criar `src/main/java/br/com/fiap/hackaton/auth/security/JwtTokenService.java`:

```java
package br.com.fiap.hackaton.auth.security;

import br.com.fiap.hackaton.auth.user.User;
import io.jsonwebtoken.Jwts;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.springframework.stereotype.Service;

@Service
public class JwtTokenService {

  private static final String ISSUER = "fiapx-auth";
  private static final Duration EXPIRATION = Duration.ofMinutes(15);

  private final PrivateKey privateKey;

  public JwtTokenService(PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  public String generateToken(User user) {
    Instant now = Instant.now();

    return Jwts.builder()
        .subject(user.getId().toString())
        .claim("email", user.getEmail())
        .claim("name", user.getName())
        .issuer(ISSUER)
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plus(EXPIRATION)))
        .signWith(privateKey, Jwts.SIG.RS256)
        .compact();
  }
}
```

- [ ] **Step 6: Adicionar as propriedades das chaves ao `application.yml` (sem default)**

Em `src/main/resources/application.yml`, dentro do bloco `app.security` já existente (ao lado de `password-pepper`), adicionar:

```yaml
app:
  security:
    password-pepper: ${PASSWORD_PEPPER}
    jwt:
      private-key: ${JWT_PRIVATE_KEY}
      public-key: ${JWT_PUBLIC_KEY}
```

- [ ] **Step 7: Adicionar as chaves de dev ao `docker-compose.yml`**

No `docker-compose.yml`, no bloco `environment` do serviço `auth-service`, adicionar (após `PASSWORD_PEPPER`):

```yaml
      - JWT_PRIVATE_KEY=MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC8lw1/LUio9/sSKCJfc2QIYMOlMOf5VTHS0968XrKgQ7fA/IsZIO9v7bph1+iOQMZxKt3DSSd28UKXbp1eNdC9eSPO3XVQdHvTupgt36579dTKgDDEPWV7+C6rNgpJN3qcnF5DAmOzEhPGRv0omI7TBrhZ3fxgMTZIDMyUxgeM65JSGuaE7suol5Q9zOxExxar8krYD082xNyCD0EBOBDyUdxQRl2G66x6C+iaTx2S2w0Q1ZnQQ21obxUX6uOh21huOdf8KhTr2mq6m59+9HuDwX9szSHvg/B6Jx9gym+YQhwuLdJU+w1pMrQlQWZkbzW8I95hswBMnpU2nUCwXelFAgMBAAECggEABqqdnYXvmu7Of0ElReksULzVmFH26/ITsCIxLh4i2QDLzr9JTiVt5q+pS6rNhl8fz1b2k9/9dyTmzQzp9ISZJmQmhzoo2s6N+gQPO7/mc8H9jahOZlbNRD6XrRGx92NGAEyUFcZQg+n7Ak1MHFKYPzluQYRUAYp7zWbhFyPmQcLv03J6RS0r8SDElro065yfw8BEV8/jode3fw3NzUiaoskcjNrPhBPuSCfxGG6n4dHWolQEQjwCHoBOPCPB6L7w+krGL5oyDnni1FRRQzBDX3LHZym6XMExSw+QlZgUD7K0AgTYon7hA28MJedCi0+Ff7Kd1wo8KQDpAeIT6t1wQQKBgQDkWi9o/+dYZl6Zer31kvs/3yqMXJsW7E8l0b/2/QHoHIYVLkuQfvrctfn3MdoJR34QX9BrlIDZkKybnpx1SVL/LnGqEYhZxkS603j0tYjT4B9ozb9y6o3igMdTg4thWlBZCQoWCc0W8wfGDeW6amKthV5FTNyzFp7WWccMIP1zWQKBgQDTbG5IvLX++c0V7Y0fv4yNdS8qQFiCEC+UfqkSIPinnQZrDNVo4+dqdhp/ZpHGhV8lohEyjVsbaUhlrmwwHQ+1kUmQJkL05x6kF459dhReXs86It6pXgCoW0JeMLa7dnAQRT0UQOtrj5Oo9VCSbJjbGrDys3A2BAG7wSoi7DKDzQKBgQCO44QBLwhjf4M4hN6y+Ssw14N3W0dMu8f3AV4evkjgJmEcheCQ5XQygciNjutBnTPcKShw+Pb7rRTlOAXtOlmuBjDn25q3mmJNiaCJd8LL2dWtrflbfjwUfMK9lnW0EGBwpkBic/Wao668ltumn4Vp0SehM6xyf/gaZwkvpMET2QKBgQCpBVFxcvQoYDn1otCkpfTOjfVj2McpS5lOJKgzZwqCrUUZRcxCq5gxAzQRz8UQqUU0h8kp2doRIu0O5Q92s3UAmaLuy7fRpAdZ9b8jS8fi3fbbKk9JpW3vKe338QfU/E2ApGm9DF1owwKwG1YLiSf2WfNGQ++cLz3XhQiTnLKRrQKBgQDRhlWNzP7KKssePEstxOiqBARrafylp2LmVc4LgTgvJhvgfxmckOjDBQb4Zya20Lo19VVyXcBLGC3HexXsYThBCL/bDm0PAfxSz6zgoRwZGeRv0UILHXMYUB9WbGa5fe9ixb6YwKNTH7kOT0/MIv/eAM81kCR9UFzJ0m005rjD9w==
      - JWT_PUBLIC_KEY=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvJcNfy1IqPf7EigiX3NkCGDDpTDn+VUx0tPevF6yoEO3wPyLGSDvb+26YdfojkDGcSrdw0kndvFCl26dXjXQvXkjzt11UHR707qYLd+ue/XUyoAwxD1le/guqzYKSTd6nJxeQwJjsxITxkb9KJiO0wa4Wd38YDE2SAzMlMYHjOuSUhrmhO7LqJeUPczsRMcWq/JK2A9PNsTcgg9BATgQ8lHcUEZdhuusegvomk8dktsNENWZ0ENtaG8VF+rjodtYbjnX/CoU69pqupuffvR7g8F/bM0h74PweicfYMpvmEIcLi3SVPsNaTK0JUFmZG81vCPeYbMATJ6VNp1AsF3pRQIDAQAB
```

- [ ] **Step 8: Rodar o teste e confirmar que passa**

Run: `./mvnw test -Dtest=JwtTokenServiceTest`
Expected: PASS — `generatesTokenWithExpectedClaimsSignedWithRs256` passa, comprovando assinatura RS256 válida (verificada com a `PublicKey`), claims `sub`/`email`/`name`/`iss` corretos, e janela de expiração de exatamente 15 minutos.

- [ ] **Step 9: Rodar a suíte completa e confirmar que nada quebrou**

Run: `./mvnw test`
Expected: PASS — todos os testes da AUTH-1/AUTH-2 continuam passando (o contexto Spring agora também carrega os beans `PrivateKey`/`PublicKey`), mais o novo `JwtTokenServiceTest`.

- [ ] **Step 10: Commit**

```bash
git add pom.xml src/main/resources/application.yml docker-compose.yml src/main/java/br/com/fiap/hackaton/auth/config/JwtKeyConfig.java src/main/java/br/com/fiap/hackaton/auth/security/JwtTokenService.java src/test/java/br/com/fiap/hackaton/auth/security/JwtTokenServiceTest.java
git commit -m "feat(auth-3): add RSA key loading and RS256 JWT token generation"
```

---

### Task 2: Serviço de autenticação (login) com mitigação de canal lateral por tempo

**Files:**
- Create: `src/main/java/br/com/fiap/hackaton/auth/user/LoginRequest.java`
- Create: `src/main/java/br/com/fiap/hackaton/auth/user/InvalidCredentialsException.java`
- Create: `src/main/java/br/com/fiap/hackaton/auth/user/AuthenticationService.java`
- Test: `src/test/java/br/com/fiap/hackaton/auth/user/AuthenticationServiceTest.java`

**Interfaces:**
- Consumes: `UserRepository.findByEmail(String): Optional<User>` (AUTH-1); `PasswordEncoder` peppered (AUTH-2, via interface); `JwtTokenService.generateToken(User): String` (Task 1).
- Produces: `record LoginRequest(String email, String password)`; `InvalidCredentialsException extends RuntimeException` (mensagem fixa "Invalid credentials"); `AuthenticationService.login(LoginRequest): String` — usado pela Task 3.

- [ ] **Step 1: Escrever o teste de serviço que falha**

Criar `src/test/java/br/com/fiap/hackaton/auth/user/AuthenticationServiceTest.java`:

```java
package br.com.fiap.hackaton.auth.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.jsonwebtoken.Jwts;
import java.security.PublicKey;
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
class AuthenticationServiceTest {

  @Container
  @ServiceConnection
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

  @Autowired private AuthenticationService authenticationService;
  @Autowired private UserRepository userRepository;
  @Autowired private PasswordEncoder passwordEncoder;
  @Autowired private PublicKey jwtPublicKey;

  @Test
  void returnsValidTokenForCorrectCredentials() {
    String rawPassword = "SenhaCorreta123";
    userRepository.saveAndFlush(
        new User(
            "Igor Matos",
            "igor.login@example.com",
            passwordEncoder.encode(rawPassword),
            UserRole.USER));

    String token =
        authenticationService.login(new LoginRequest("igor.login@example.com", rawPassword));

    var claims =
        Jwts.parser().verifyWith(jwtPublicKey).build().parseSignedClaims(token).getPayload();
    assertThat(claims.get("email", String.class)).isEqualTo("igor.login@example.com");
  }

  @Test
  void throwsInvalidCredentialsWhenPasswordIsWrong() {
    userRepository.saveAndFlush(
        new User(
            "Julia Reis",
            "julia.login@example.com",
            passwordEncoder.encode("SenhaCorreta123"),
            UserRole.USER));

    assertThatThrownBy(
            () ->
                authenticationService.login(
                    new LoginRequest("julia.login@example.com", "SenhaErrada999")))
        .isInstanceOf(InvalidCredentialsException.class);
  }

  @Test
  void throwsInvalidCredentialsWhenEmailIsUnknown() {
    assertThatThrownBy(
            () ->
                authenticationService.login(
                    new LoginRequest("nao.existe@example.com", "QualquerSenha123")))
        .isInstanceOf(InvalidCredentialsException.class);
  }

  @Test
  void wrongPasswordAndUnknownEmailProduceTheSameExceptionMessage() {
    userRepository.saveAndFlush(
        new User(
            "Karla Nunes",
            "karla.login@example.com",
            passwordEncoder.encode("SenhaCorreta123"),
            UserRole.USER));

    String wrongPasswordMessage = loginAndCaptureMessage("karla.login@example.com", "Errada123");
    String unknownEmailMessage = loginAndCaptureMessage("ninguem@example.com", "Errada123");

    assertThat(wrongPasswordMessage).isEqualTo(unknownEmailMessage);
  }

  private String loginAndCaptureMessage(String email, String password) {
    try {
      authenticationService.login(new LoginRequest(email, password));
      throw new AssertionError("expected InvalidCredentialsException");
    } catch (InvalidCredentialsException ex) {
      return ex.getMessage();
    }
  }
}
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `./mvnw test -Dtest=AuthenticationServiceTest`
Expected: FAIL — compilação quebra (`LoginRequest`, `InvalidCredentialsException`, `AuthenticationService` ainda não existem).

- [ ] **Step 3: Criar `LoginRequest`**

Criar `src/main/java/br/com/fiap/hackaton/auth/user/LoginRequest.java`:

```java
package br.com.fiap.hackaton.auth.user;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
    @NotBlank(message = "email is required") String email,
    @NotBlank(message = "password is required") String password) {

  @Override
  public String toString() {
    return "LoginRequest[email=" + email + ", password=***]";
  }
}
```

- [ ] **Step 4: Criar `InvalidCredentialsException`**

Criar `src/main/java/br/com/fiap/hackaton/auth/user/InvalidCredentialsException.java`:

```java
package br.com.fiap.hackaton.auth.user;

public class InvalidCredentialsException extends RuntimeException {

  public InvalidCredentialsException() {
    super("Invalid credentials");
  }
}
```

- [ ] **Step 5: Criar `AuthenticationService`**

Criar `src/main/java/br/com/fiap/hackaton/auth/user/AuthenticationService.java`:

```java
package br.com.fiap.hackaton.auth.user;

import br.com.fiap.hackaton.auth.security.JwtTokenService;
import java.util.Locale;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtTokenService jwtTokenService;
  private final String dummyPasswordHash;

  public AuthenticationService(
      UserRepository userRepository,
      PasswordEncoder passwordEncoder,
      JwtTokenService jwtTokenService) {
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
    this.jwtTokenService = jwtTokenService;
    this.dummyPasswordHash = passwordEncoder.encode("dummy-password-for-timing-safety");
  }

  public String login(LoginRequest request) {
    String normalizedEmail = request.email().trim().toLowerCase(Locale.ROOT);
    User user = userRepository.findByEmail(normalizedEmail).orElse(null);

    String hashToCheck = user != null ? user.getPasswordHash() : dummyPasswordHash;
    boolean passwordMatches = passwordEncoder.matches(request.password(), hashToCheck);

    if (user == null || !passwordMatches) {
      throw new InvalidCredentialsException();
    }

    return jwtTokenService.generateToken(user);
  }
}
```

- [ ] **Step 6: Rodar o teste e confirmar que passa**

Run: `./mvnw test -Dtest=AuthenticationServiceTest`
Expected: PASS — os 4 testes passam, incluindo `wrongPasswordAndUnknownEmailProduceTheSameExceptionMessage`, que prova que os dois motivos de falha são indistinguíveis pela mensagem.

- [ ] **Step 7: Commit**

```bash
git add src/main/java/br/com/fiap/hackaton/auth/user/LoginRequest.java src/main/java/br/com/fiap/hackaton/auth/user/InvalidCredentialsException.java src/main/java/br/com/fiap/hackaton/auth/user/AuthenticationService.java src/test/java/br/com/fiap/hackaton/auth/user/AuthenticationServiceTest.java
git commit -m "feat(auth-3): add login authentication service with timing-safe unknown-email handling"
```

---

### Task 3: Endpoint `POST /auth/login`

**Files:**
- Create: `src/main/java/br/com/fiap/hackaton/auth/user/LoginResponse.java`
- Modify: `src/main/java/br/com/fiap/hackaton/auth/user/AuthController.java`
- Modify: `src/main/java/br/com/fiap/hackaton/auth/web/GlobalExceptionHandler.java`
- Test: `src/test/java/br/com/fiap/hackaton/auth/user/AuthControllerLoginTest.java`

**Interfaces:**
- Consumes: `AuthenticationService.login(LoginRequest): String` e `InvalidCredentialsException` (Task 2).
- Produces: `POST /auth/login` retornando `200` com `LoginResponse(String token)`; `401` com `ErrorResponse(String message)` (reaproveitado da AUTH-2) em credencial inválida, mensagem fixa "Invalid credentials" idêntica para senha errada e e-mail inexistente.

- [ ] **Step 1: Escrever o teste HTTP que falha**

Criar `src/test/java/br/com/fiap/hackaton/auth/user/AuthControllerLoginTest.java`:

```java
package br.com.fiap.hackaton.auth.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import io.jsonwebtoken.Jwts;
import java.security.PublicKey;
import org.junit.jupiter.api.Test;
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
class AuthControllerLoginTest {

  @Container
  @ServiceConnection
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository userRepository;
  @Autowired private PasswordEncoder passwordEncoder;
  @Autowired private PublicKey jwtPublicKey;

  @Test
  void loginWithCorrectCredentialsReturns200WithValidRs256Token() throws Exception {
    String rawPassword = "SenhaValida123";
    userRepository.saveAndFlush(
        new User(
            "Laura Prado",
            "laura.login@example.com",
            passwordEncoder.encode(rawPassword),
            UserRole.USER));

    String payload =
        """
        {"email":"laura.login@example.com","password":"%s"}
        """
            .formatted(rawPassword);

    var result =
        mockMvc
            .perform(post("/auth/login").contentType("application/json").content(payload))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").exists())
            .andReturn();

    String token =
        JsonPath.read(result.getResponse().getContentAsString(), "$.token");
    var claims =
        Jwts.parser().verifyWith(jwtPublicKey).build().parseSignedClaims(token).getPayload();

    assertThat(claims.getIssuer()).isEqualTo("fiapx-auth");
    assertThat(claims.get("email", String.class)).isEqualTo("laura.login@example.com");
    assertThat(claims.get("name", String.class)).isEqualTo("Laura Prado");
  }

  @Test
  void loginWithWrongPasswordReturns401Generic() throws Exception {
    userRepository.saveAndFlush(
        new User(
            "Marcelo Dias",
            "marcelo.login@example.com",
            passwordEncoder.encode("SenhaValida123"),
            UserRole.USER));

    String payload =
        """
        {"email":"marcelo.login@example.com","password":"SenhaErrada999"}
        """;

    mockMvc
        .perform(post("/auth/login").contentType("application/json").content(payload))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.message").value("Invalid credentials"));
  }

  @Test
  void loginWithUnknownEmailReturns401WithSameGenericMessageAsWrongPassword() throws Exception {
    String payload =
        """
        {"email":"nao.registrado@example.com","password":"QualquerSenha123"}
        """;

    mockMvc
        .perform(post("/auth/login").contentType("application/json").content(payload))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.message").value("Invalid credentials"));
  }
}
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `./mvnw test -Dtest=AuthControllerLoginTest`
Expected: FAIL — compilação quebra (`LoginResponse` ainda não existe; `AuthController` ainda não tem o método `login`; sem ele não há rota `/auth/login`).

- [ ] **Step 3: Criar `LoginResponse`**

Criar `src/main/java/br/com/fiap/hackaton/auth/user/LoginResponse.java`:

```java
package br.com.fiap.hackaton.auth.user;

public record LoginResponse(String token) {}
```

- [ ] **Step 4: Adicionar o handler de `InvalidCredentialsException` ao `GlobalExceptionHandler`**

Em `src/main/java/br/com/fiap/hackaton/auth/web/GlobalExceptionHandler.java`, adicionar o import e o novo `@ExceptionHandler`, mantendo os dois já existentes (`EmailAlreadyRegisteredException` → 409, `MethodArgumentNotValidException` → 400):

```java
package br.com.fiap.hackaton.auth.web;

import br.com.fiap.hackaton.auth.user.EmailAlreadyRegisteredException;
import br.com.fiap.hackaton.auth.user.InvalidCredentialsException;
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

  @ExceptionHandler(InvalidCredentialsException.class)
  public ResponseEntity<ErrorResponse> handleInvalidCredentials(InvalidCredentialsException ex) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse(ex.getMessage()));
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

- [ ] **Step 5: Adicionar o método `login` ao `AuthController`**

Substituir o conteúdo de `src/main/java/br/com/fiap/hackaton/auth/user/AuthController.java` por:

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
  private final AuthenticationService authenticationService;

  public AuthController(
      UserRegistrationService userRegistrationService,
      AuthenticationService authenticationService) {
    this.userRegistrationService = userRegistrationService;
    this.authenticationService = authenticationService;
  }

  @PostMapping("/register")
  public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
    User registeredUser = userRegistrationService.register(request);
    return ResponseEntity.status(HttpStatus.CREATED).body(UserResponse.from(registeredUser));
  }

  @PostMapping("/login")
  public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
    String token = authenticationService.login(request);
    return ResponseEntity.ok(new LoginResponse(token));
  }
}
```

- [ ] **Step 6: Rodar o teste e confirmar que passa**

Run: `./mvnw test -Dtest=AuthControllerLoginTest`
Expected: PASS — os 3 testes (`loginWithCorrectCredentialsReturns200WithValidRs256Token`, `loginWithWrongPasswordReturns401Generic`, `loginWithUnknownEmailReturns401WithSameGenericMessageAsWrongPassword`) passam.

- [ ] **Step 7: Rodar a suíte completa**

Run: `./mvnw test`
Expected: PASS — todos os testes da AUTH-1/AUTH-2 (inalterados) mais os novos da AUTH-3 (`JwtTokenServiceTest`, `AuthenticationServiceTest`, `AuthControllerLoginTest`) passam.

- [ ] **Step 8: Commit**

```bash
git add src/main/java/br/com/fiap/hackaton/auth/user/LoginResponse.java src/main/java/br/com/fiap/hackaton/auth/user/AuthController.java src/main/java/br/com/fiap/hackaton/auth/web/GlobalExceptionHandler.java src/test/java/br/com/fiap/hackaton/auth/user/AuthControllerLoginTest.java
git commit -m "feat(auth-3): add POST /auth/login endpoint"
```
