package br.com.fiap.hackaton.auth.config;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class JwtKeyPairConsistencyValidator implements ApplicationRunner {

  private final PrivateKey privateKey;
  private final PublicKey publicKey;

  public JwtKeyPairConsistencyValidator(PrivateKey privateKey, PublicKey publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  @Override
  public void run(ApplicationArguments args) {
    RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) privateKey;
    RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;

    if (!rsaPrivateKey.getModulus().equals(rsaPublicKey.getModulus())) {
      throw new IllegalStateException(
          "JWT_PRIVATE_KEY and JWT_PUBLIC_KEY do not form a matching RSA key pair");
    }
  }
}
