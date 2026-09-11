package br.com.fiap.hackaton.security.commons;

import java.util.List;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@AutoConfiguration
@ConditionalOnClass(WebMvcConfigurer.class)
public class WebMvcAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public CurrentUserIdArgumentResolver currentUserIdArgumentResolver() {
    return new CurrentUserIdArgumentResolver();
  }

  @Bean
  public WebMvcConfigurer securityCommonsWebMvcConfigurer(CurrentUserIdArgumentResolver resolver) {
    return new WebMvcConfigurer() {
      @Override
      public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(resolver);
      }
    };
  }
}
