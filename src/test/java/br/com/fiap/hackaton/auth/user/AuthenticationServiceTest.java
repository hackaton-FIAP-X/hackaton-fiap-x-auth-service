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
