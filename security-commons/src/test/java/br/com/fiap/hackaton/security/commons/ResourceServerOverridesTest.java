package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

class ResourceServerOverridesTest {

  @Nested
  @SpringBootTest(
      webEnvironment = WebEnvironment.RANDOM_PORT,
      classes = CustomFilterChainConfig.class,
      properties = "security.jwt.jwks-uri=https://issuer.example/jwks.json")
  class CustomFilterChain {

    @LocalServerPort private int appPort;
    @Autowired private TestRestTemplate restTemplate;

    @Test
    void consumerSuppliedSecurityFilterChainBacksOffTheDefault() {
      ResponseEntity<String> response =
          restTemplate.getForEntity("http://localhost:" + appPort + "/me", String.class);

      assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
      assertThat(response.getBody()).isEqualTo("permitted by custom chain");
    }
  }

  @Nested
  @SpringBootTest(
      webEnvironment = WebEnvironment.RANDOM_PORT,
      classes = CustomEntryPointConfig.class,
      properties = "security.jwt.jwks-uri=https://issuer.example/jwks.json")
  class CustomEntryPoint {

    @LocalServerPort private int appPort;
    @Autowired private TestRestTemplate restTemplate;

    @Test
    void consumerSuppliedProblemDetailAuthEntryPointBacksOffTheDefault() {
      ResponseEntity<String> response =
          restTemplate.getForEntity("http://localhost:" + appPort + "/me", String.class);

      assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
      assertThat(response.getHeaders().getFirst("X-Custom-Entry-Point")).isEqualTo("true");
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @Import(CustomChainMeController.class)
  static class CustomFilterChainConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
      return http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll()).build();
    }
  }

  @RestController
  static class CustomChainMeController {
    @GetMapping("/me")
    String me() {
      return "permitted by custom chain";
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @Import(CustomEntryPointMeController.class)
  static class CustomEntryPointConfig {

    @Bean
    ProblemDetailAuthEntryPoint problemDetailAuthEntryPoint(ObjectMapper objectMapper) {
      return new ProblemDetailAuthEntryPoint(objectMapper) {
        @Override
        public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception)
            throws IOException {
          response.setHeader("X-Custom-Entry-Point", "true");
          super.commence(request, response, exception);
        }
      };
    }
  }

  @RestController
  static class CustomEntryPointMeController {
    @GetMapping("/me")
    String me() {
      return "unreachable without a token";
    }
  }
}
