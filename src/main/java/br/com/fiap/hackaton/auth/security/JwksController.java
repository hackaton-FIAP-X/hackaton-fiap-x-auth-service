package br.com.fiap.hackaton.auth.security;

import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.Jwks;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwksController {

  private static final String CACHE_CONTROL = "public, max-age=3600";

  private final Map<String, Object> jwkSet;

  public JwksController(PublicKey jwtPublicKey) {
    Jwk<?> jwk = Jwks.builder().key(jwtPublicKey).idFromThumbprint().algorithm("RS256").build();
    this.jwkSet = Map.of("keys", List.of(jwk));
  }

  @GetMapping("/.well-known/jwks.json")
  public ResponseEntity<Map<String, Object>> jwks() {
    return ResponseEntity.ok().header(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL).body(jwkSet);
  }
}
