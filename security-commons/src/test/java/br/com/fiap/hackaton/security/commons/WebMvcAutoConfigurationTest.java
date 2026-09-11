package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

class WebMvcAutoConfigurationTest {

  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(WebMvcAutoConfiguration.class));

  @Test
  void registersTheCurrentUserIdArgumentResolver() {
    contextRunner.run(
        (AssertableApplicationContext context) -> {
          assertThat(context).hasSingleBean(CurrentUserIdArgumentResolver.class);
          WebMvcConfigurer configurer = context.getBean(WebMvcConfigurer.class);
          List<HandlerMethodArgumentResolver> resolvers = new ArrayList<>();
          configurer.addArgumentResolvers(resolvers);
          assertThat(resolvers).hasSize(1).first().isInstanceOf(CurrentUserIdArgumentResolver.class);
        });
  }
}
