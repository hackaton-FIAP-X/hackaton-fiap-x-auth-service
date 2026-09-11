package br.com.fiap.hackaton.security.commons;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.jwt")
public record SecurityCommonsProperties(String jwksUri, String issuer, List<String> publicEndpoints) {

  static final List<String> DEFAULT_PUBLIC_ENDPOINTS =
      List.of(
          "/actuator/health",
          "/actuator/health/**",
          "/actuator/info",
          "/actuator/prometheus",
          "/api-docs",
          "/api-docs/**",
          "/swagger-ui.html",
          "/swagger-ui/**");

  public SecurityCommonsProperties {
    if (publicEndpoints == null || publicEndpoints.isEmpty()) {
      publicEndpoints = DEFAULT_PUBLIC_ENDPOINTS;
    }
  }
}
