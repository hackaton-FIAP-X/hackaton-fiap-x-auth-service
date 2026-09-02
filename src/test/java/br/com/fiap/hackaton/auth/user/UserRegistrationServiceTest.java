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
