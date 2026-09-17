package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    classes = ResourceServerPublicEndpointsTest.TestApp.class,
    properties = {
      "security.jwt.jwks-uri=https://issuer.example/jwks.json",
      "security.jwt.public-endpoints=/public"
    })
class ResourceServerPublicEndpointsTest {

  @LocalServerPort private int appPort;

  @Autowired private TestRestTemplate restTemplate;

  @Test
  void configuredPublicEndpointIsAccessibleWithoutAToken() {
    ResponseEntity<String> response = restTemplate.getForEntity(url("/public"), String.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).isEqualTo("ok");
  }

  @Test
  void nonPublicEndpointStillRequiresAToken() {
    ResponseEntity<String> response = restTemplate.getForEntity(url("/private"), String.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  private String url(String path) {
    return "http://localhost:" + appPort + path;
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @Import(TestController.class)
  static class TestApp {}

  @RestController
  static class TestController {
    @GetMapping("/public")
    String publicEndpoint() {
      return "ok";
    }

    @GetMapping("/private")
    String privateEndpoint() {
      return "ok";
    }
  }
}
