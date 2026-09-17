package br.com.fiap.hackaton.security.commons;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;

@AutoConfiguration
@AutoConfigureBefore(SecurityAutoConfiguration.class)
@EnableConfigurationProperties(SecurityCommonsProperties.class)
@ConditionalOnWebApplication(type = Type.SERVLET)
@ConditionalOnProperty(prefix = "security.jwt", name = "jwks-uri")
public class ResourceServerAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public JwtDecoder jwtDecoder(
      SecurityCommonsProperties properties, OAuth2TokenValidator<Jwt> jwtTokenValidator) {
    NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(properties.jwksUri()).build();
    decoder.setJwtValidator(jwtTokenValidator);
    return decoder;
  }

  @Bean
  @ConditionalOnMissingBean
  public OAuth2TokenValidator<Jwt> jwtTokenValidator(SecurityCommonsProperties properties) {
    OAuth2TokenValidator<Jwt> defaults =
        StringUtils.hasText(properties.issuer())
            ? JwtValidators.createDefaultWithIssuer(properties.issuer())
            : JwtValidators.createDefault();
    return new DelegatingOAuth2TokenValidator<>(defaults, new SubjectIsUuidValidator());
  }

  @Bean
  @ConditionalOnMissingBean(ProblemDetailAuthEntryPoint.class)
  public ProblemDetailAuthEntryPoint problemDetailAuthEntryPoint(ObjectMapper objectMapper) {
    return new ProblemDetailAuthEntryPoint(objectMapper);
  }

  @Bean
  @ConditionalOnMissingBean(SecurityFilterChain.class)
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      JwtDecoder jwtDecoder,
      SecurityCommonsProperties properties,
      ProblemDetailAuthEntryPoint responder)
      throws Exception {
    String[] publicEndpoints = properties.publicEndpoints().toArray(new String[0]);
    return http.csrf(csrf -> csrf.disable())
        .cors(Customizer.withDefaults())
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(
            requests ->
                requests
                    .requestMatchers(HttpMethod.OPTIONS, "/**")
                    .permitAll()
                    .requestMatchers(publicEndpoints)
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .oauth2ResourceServer(
            oauth2 ->
                oauth2
                    .jwt(jwt -> jwt.decoder(jwtDecoder))
                    .authenticationEntryPoint(responder)
                    .accessDeniedHandler(responder))
        .exceptionHandling(
            exceptions ->
                exceptions.authenticationEntryPoint(responder).accessDeniedHandler(responder))
        .build();
  }
}
