package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
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
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A consumer that overrides only the {@link OAuth2TokenValidator} bean (not the whole {@link
 * org.springframework.security.oauth2.jwt.JwtDecoder}) opts out of the built-in {@link
 * SubjectIsUuidValidator} guarantee explicitly and in isolation, without losing the rest of the
 * decoder's JWKS-based configuration.
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    classes = ResourceServerCustomValidatorEndToEndTest.TestApp.class)
class ResourceServerCustomValidatorEndToEndTest {

  private static KeyPair keyPair;
  private static HttpServer jwksServer;
  private static int jwksPort;

  @LocalServerPort private int appPort;

  @Autowired private TestRestTemplate restTemplate;

  @BeforeAll
  static void startJwksStub() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    keyPair = generator.generateKeyPair();

    RSAKey jwk =
        new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .privateKey((RSAPrivateKey) keyPair.getPrivate())
            .keyID("test-key")
            .build()
            .toPublicJWK();
    String jwksJson = "{\"keys\":[" + jwk.toJSONString() + "]}";

    jwksServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    jwksServer.createContext(
        "/.well-known/jwks.json",
        exchange -> {
          byte[] body = jwksJson.getBytes(StandardCharsets.UTF_8);
          exchange.getResponseHeaders().add("Content-Type", "application/json");
          exchange.sendResponseHeaders(200, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    jwksServer.start();
    jwksPort = jwksServer.getAddress().getPort();
  }

  @AfterAll
  static void stopJwksStub() {
    jwksServer.stop(0);
  }

  @DynamicPropertySource
  static void jwksUri(DynamicPropertyRegistry registry) {
    registry.add(
        "security.jwt.jwks-uri", () -> "http://localhost:" + jwksPort + "/.well-known/jwks.json");
  }

  @Test
  void consumerSuppliedValidatorReplacesTheBuiltInSubjectUuidCheck() throws Exception {
    String token = signToken("not-a-uuid");

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    ResponseEntity<String> response =
        restTemplate.exchange(url("/me"), HttpMethod.GET, new HttpEntity<>(headers), String.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  private String url(String path) {
    return "http://localhost:" + appPort + path;
  }

  private static String signToken(String subject) throws Exception {
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject(subject)
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(300)))
            .build();
    SignedJWT jwt =
        new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test-key").build(), claims);
    jwt.sign(new RSASSASigner(keyPair.getPrivate()));
    return jwt.serialize();
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @Import(MeController.class)
  static class TestApp {

    @Bean
    OAuth2TokenValidator<Jwt> jwtTokenValidator() {
      return JwtValidators.createDefault();
    }
  }

  @RestController
  static class MeController {
    @GetMapping("/me")
    String me() {
      return "ok";
    }
  }
}
