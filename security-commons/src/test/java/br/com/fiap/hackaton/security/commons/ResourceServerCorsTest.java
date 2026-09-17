package br.com.fiap.hackaton.security.commons;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@SpringBootTest(
    classes = ResourceServerCorsTest.TestApp.class,
    properties = "security.jwt.jwks-uri=https://issuer.example/jwks.json")
@AutoConfigureMockMvc
class ResourceServerCorsTest {

  @Autowired private MockMvc mockMvc;

  @Test
  void preflightRequestFromAnAllowedOriginGetsCorsHeaders() throws Exception {
    mockMvc
        .perform(
            options("/public")
                .header(HttpHeaders.ORIGIN, "https://allowed.example")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET"))
        .andExpect(status().isOk())
        .andExpect(
            header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "https://allowed.example"));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @Import(PublicController.class)
  static class TestApp {

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
      CorsConfiguration configuration = new CorsConfiguration();
      configuration.setAllowedOrigins(List.of("https://allowed.example"));
      configuration.setAllowedMethods(List.of("GET"));
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      source.registerCorsConfiguration("/**", configuration);
      return source;
    }
  }

  @RestController
  static class PublicController {
    @GetMapping("/public")
    String publicEndpoint() {
      return "ok";
    }
  }
}
