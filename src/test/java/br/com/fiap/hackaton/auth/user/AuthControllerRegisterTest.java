package br.com.fiap.hackaton.auth.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
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

  @Container @ServiceConnection
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
    // Test 1: Happy path (201 CREATED)
    String rawPassword = "SenhaQueNuncaDeveApareceNoLog99";
    String payload =
        """
        {"name":"Elis Costa","email":"elis.registro@example.com","password":"%s"}
        """
            .formatted(rawPassword);

    mockMvc
        .perform(post("/auth/register").contentType("application/json").content(payload))
        .andExpect(status().isCreated());

    assertThat(logContainsPasswordAnywhere(rawPassword)).isFalse();

    // Test 2: Validation failure path (400 BAD_REQUEST) - highest risk path
    // Spring's validation error machinery may log rejected values; this proves it doesn't
    String shortPassword = "abc123";
    String validationFailurePayload =
        """
        {"name":"Fátima Silva","email":"fatima.registro@example.com","password":"%s"}
        """
            .formatted(shortPassword);

    mockMvc
        .perform(
            post("/auth/register")
                .contentType("application/json")
                .content(validationFailurePayload))
        .andExpect(status().isBadRequest());

    assertThat(logContainsPasswordAnywhere(shortPassword)).isFalse();
  }

  private boolean logContainsPasswordAnywhere(String password) {
    return logAppender.list.stream()
        .anyMatch(
            event ->
                event.getFormattedMessage().contains(password)
                    || throwableProxyContainsPassword(event.getThrowableProxy(), password));
  }

  private static boolean throwableProxyContainsPassword(IThrowableProxy proxy, String password) {
    while (proxy != null) {
      String message = proxy.getMessage();
      if (message != null && message.contains(password)) {
        return true;
      }
      proxy = proxy.getCause();
    }
    return false;
  }
}
