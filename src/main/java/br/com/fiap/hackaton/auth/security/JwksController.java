package br.com.fiap.hackaton.auth.security;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.Jwks;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@Tag(name = "JWKS", description = "Publicacao da chave publica usada para validar os tokens JWT")
public class JwksController {

  private static final String CACHE_CONTROL = "public, max-age=3600";

  private final Map<String, Object> jwkSet;

  public JwksController(PublicKey jwtPublicKey) {
    // publicKeyUse("sig") vira o campo "use" do JWK (RFC 7517): diz que a chave
    // serve para assinatura, nao para cifra. Clientes que filtram por "use"
    // ignoram a chave quando ele falta.
    Jwk<?> jwk =
        Jwks.builder()
            .key(jwtPublicKey)
            .idFromThumbprint()
            .algorithm("RS256")
            .publicKeyUse("sig")
            .build();
    this.jwkSet = Map.of("keys", List.of(jwk));
  }

  @Operation(summary = "Publica o conjunto de chaves publicas (JWK Set) em formato RFC 7517")
  @ApiResponse(responseCode = "200", description = "JWK Set contendo a chave publica RS256 ativa")
  @GetMapping("/.well-known/jwks.json")
  public ResponseEntity<Map<String, Object>> jwks() {
    return ResponseEntity.ok().header(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL).body(jwkSet);
  }
}
