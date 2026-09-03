package br.com.fiap.hackaton.auth.security;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.security.crypto.password.PasswordEncoder;

public class PepperedPasswordEncoder implements PasswordEncoder {

  private static final String HMAC_ALGORITHM = "HmacSHA256";

  private final PasswordEncoder delegate;
  private final SecretKeySpec pepperKey;

  public PepperedPasswordEncoder(PasswordEncoder delegate, String pepper) {
    this.delegate = delegate;
    this.pepperKey = new SecretKeySpec(pepper.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
  }

  @Override
  public String encode(CharSequence rawPassword) {
    return delegate.encode(applyPepper(rawPassword));
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    return delegate.matches(applyPepper(rawPassword), encodedPassword);
  }

  private String applyPepper(CharSequence rawPassword) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(pepperKey);
      byte[] hmac = mac.doFinal(rawPassword.toString().getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(hmac);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Unable to apply password pepper", e);
    }
  }
}
