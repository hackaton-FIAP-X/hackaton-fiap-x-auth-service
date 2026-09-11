package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class SecurityCommonsPropertiesTest {

  @Test
  void defaultsPublicEndpointsWhenNullIsGiven() {
    var properties = new SecurityCommonsProperties("https://issuer/jwks.json", "fiapx-auth", null);

    assertThat(properties.publicEndpoints())
        .containsExactlyInAnyOrder(
            "/actuator/health",
            "/actuator/health/**",
            "/actuator/info",
            "/actuator/prometheus",
            "/api-docs",
            "/api-docs/**",
            "/swagger-ui.html",
            "/swagger-ui/**");
  }

  @Test
  void defaultsPublicEndpointsWhenEmptyListIsGiven() {
    var properties = new SecurityCommonsProperties("https://issuer/jwks.json", null, List.of());

    assertThat(properties.publicEndpoints()).isNotEmpty();
  }

  @Test
  void keepsExplicitPublicEndpointsWhenProvided() {
    var properties =
        new SecurityCommonsProperties("https://issuer/jwks.json", null, List.of("/custom-health"));

    assertThat(properties.publicEndpoints()).containsExactly("/custom-health");
  }
}
