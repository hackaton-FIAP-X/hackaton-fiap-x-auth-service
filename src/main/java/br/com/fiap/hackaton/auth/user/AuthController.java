package br.com.fiap.hackaton.auth.user;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

  private final UserRegistrationService userRegistrationService;

  public AuthController(UserRegistrationService userRegistrationService) {
    this.userRegistrationService = userRegistrationService;
  }

  @PostMapping("/register")
  public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
    User registeredUser = userRegistrationService.register(request);
    return ResponseEntity.status(HttpStatus.CREATED).body(UserResponse.from(registeredUser));
  }
}
