package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

class ResourceServerAutoConfigurationTest {

  private final WebApplicationContextRunner contextRunner =
      new WebApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(
                  WebMvcAutoConfiguration.class,
                  SecurityAutoConfiguration.class,
                  ResourceServerAutoConfiguration.class))
          .withBean(ObjectMapper.class, ObjectMapper::new);

  @Test
  void doesNothingWithoutAJwksUriProperty() {
    contextRunner.run(
        (AssertableWebApplicationContext context) -> {
          assertThat(context).doesNotHaveBean(JwtDecoder.class);
          assertThat(context).doesNotHaveBean(ProblemDetailAuthEntryPoint.class);
        });
  }

  @Test
  void registersDecoderAndFilterChainWhenJwksUriIsSet() {
    contextRunner
        .withPropertyValues("security.jwt.jwks-uri=https://issuer.example/jwks.json")
        .run(
            (AssertableWebApplicationContext context) -> {
              assertThat(context).hasSingleBean(JwtDecoder.class);
              assertThat(context).hasSingleBean(SecurityFilterChain.class);
              assertThat(context).hasSingleBean(ProblemDetailAuthEntryPoint.class);
            });
  }

  @Test
  void backsOffWhenAUserSuppliedJwtDecoderExists() {
    contextRunner
        .withPropertyValues("security.jwt.jwks-uri=https://issuer.example/jwks.json")
        .withUserConfiguration(CustomJwtDecoderConfig.class)
        .run(
            (AssertableWebApplicationContext context) -> {
              assertThat(context).hasSingleBean(JwtDecoder.class);
              assertThat(context.getBean(JwtDecoder.class))
                  .isSameAs(context.getBean(CustomJwtDecoderConfig.class).decoder);
            });
  }

  @Configuration
  static class CustomJwtDecoderConfig {
    final JwtDecoder decoder =
        token -> {
          throw new UnsupportedOperationException("test double");
        };

    @Bean
    JwtDecoder jwtDecoder() {
      return decoder;
    }
  }
}
