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
