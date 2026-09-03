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
