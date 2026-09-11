package br.com.fiap.hackaton.auth.config;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtKeyConfig {

  @Bean
  public PrivateKey jwtPrivateKey(
      @Value("${app.security.jwt.private-key}") String privateKeyBase64) {
    try {
      byte[] decoded = Base64.getDecoder().decode(privateKeyBase64);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decoded));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new IllegalStateException("Unable to load JWT private key", e);
    }
  }

  @Bean
  public PublicKey jwtPublicKey(@Value("${app.security.jwt.public-key}") String publicKeyBase64) {
    try {
      byte[] decoded = Base64.getDecoder().decode(publicKeyBase64);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return keyFactory.generatePublic(new X509EncodedKeySpec(decoded));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new IllegalStateException("Unable to load JWT public key", e);
    }
  }
}
