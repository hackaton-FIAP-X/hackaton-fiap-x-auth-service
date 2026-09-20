package br.com.fiap.hackaton.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import br.com.fiap.hackaton.auth.security.PepperedPasswordEncoder;

@Configuration
public class PasswordEncoderConfig {

  @Bean
  public PasswordEncoder passwordEncoder(@Value("${app.security.password-pepper}") String pepper) {
    return new PepperedPasswordEncoder(
        Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(), pepper);
  }
}
