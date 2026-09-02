package br.com.fiap.hackaton.auth.user;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserRegistrationService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  public UserRegistrationService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
  }

  public User register(RegisterRequest request) {
    String passwordHash = passwordEncoder.encode(request.password());
    User user = new User(request.name(), request.email(), passwordHash, UserRole.USER);

    try {
      return userRepository.saveAndFlush(user);
    } catch (DataIntegrityViolationException ex) {
      throw new EmailAlreadyRegisteredException(request.email());
    }
  }
}
