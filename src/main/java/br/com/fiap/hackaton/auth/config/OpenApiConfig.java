package br.com.fiap.hackaton.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

  @Bean
  public OpenAPI authServiceOpenApi() {
    return new OpenAPI()
        .info(
            new Info()
                .title("Auth Service API")
                .version("1.0.0")
                .description(
                    "Registro, login e publicacao de chave publica (JWKS) para emissao e "
                        + "validacao de tokens JWT RS256 do ecossistema FIAP-X."));
  }
}
