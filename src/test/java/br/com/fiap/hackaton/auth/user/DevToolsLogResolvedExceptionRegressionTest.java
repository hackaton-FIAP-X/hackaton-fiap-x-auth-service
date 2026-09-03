package br.com.fiap.hackaton.auth.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Reproduces the exact condition spring-boot-devtools enables by default
 * (spring.mvc.log-resolved-exception=true). JUnit normally suppresses devtools' defaults via
 * DevToolsEnablementDeducer, which is why a plain @SpringBootTest never observes this leak. This
 * test forces the property directly on a dedicated Spring context so the leak is caught regardless
 * of whether devtools happens to be active in the running environment (e.g. under docker-compose,
 * where the Dockerfile's ENTRYPOINT runs ./mvnw spring-boot:run with devtools on the classpath).
 *
 * <p>When the property is true, WebMvcAutoConfiguration wires a warn-log category into every
 * AbstractHandlerExceptionResolver, including the one that handles @ExceptionHandler methods. That
 * resolver logs "Resolved [" + ex + "]" at WARN with no truncation. For a validation failure,
 * MethodArgumentNotValidException's message embeds each FieldError#toString(), which includes the
 * raw rejected value - i.e. the submitted password.
 */
@Testcontainers
@SpringBootTest(properties = "spring.mvc.log-resolved-exception=true")
@AutoConfigureMockMvc
class DevToolsLogResolvedExceptionRegressionTest {

  @Container @ServiceConnection
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

  @Autowired private MockMvc mockMvc;

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
  void neverLogsTheRejectedPasswordEvenWithDevToolsLogResolvedExceptionEnabled() throws Exception {
    String shortPassword = "abc123";
    String payload =
        """
        {"name":"Gilberto Melo","email":"gilberto.devtools@example.com","password":"%s"}
        """
            .formatted(shortPassword);

    mockMvc
        .perform(post("/auth/register").contentType("application/json").content(payload))
        .andExpect(status().isBadRequest());

    boolean passwordLeakedToLogs =
        logAppender.list.stream()
            .anyMatch(
                event ->
                    event.getFormattedMessage().contains(shortPassword)
                        || throwableProxyContainsPassword(
                            event.getThrowableProxy(), shortPassword));

    assertThat(passwordLeakedToLogs).isFalse();
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
