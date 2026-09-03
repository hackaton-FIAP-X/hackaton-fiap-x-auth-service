package br.com.fiap.hackaton.auth.user;

import br.com.fiap.hackaton.auth.security.JwtTokenService;
import java.util.Locale;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtTokenService jwtTokenService;
  private final String dummyPasswordHash;

  public AuthenticationService(
      UserRepository userRepository,
      PasswordEncoder passwordEncoder,
      JwtTokenService jwtTokenService) {
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
    this.jwtTokenService = jwtTokenService;
    this.dummyPasswordHash = passwordEncoder.encode("dummy-password-for-timing-safety");
  }

  public String login(LoginRequest request) {
    String normalizedEmail = request.email().trim().toLowerCase(Locale.ROOT);
    User user = userRepository.findByEmail(normalizedEmail).orElse(null);

    String hashToCheck = user != null ? user.getPasswordHash() : dummyPasswordHash;
    boolean passwordMatches = passwordEncoder.matches(request.password(), hashToCheck);

    if (user == null || !passwordMatches) {
      throw new InvalidCredentialsException();
    }

    return jwtTokenService.generateToken(user);
  }
}
