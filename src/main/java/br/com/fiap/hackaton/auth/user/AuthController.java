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
  private final AuthenticationService authenticationService;

  public AuthController(
      UserRegistrationService userRegistrationService,
      AuthenticationService authenticationService) {
    this.userRegistrationService = userRegistrationService;
    this.authenticationService = authenticationService;
  }

  @PostMapping("/register")
  public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
    User registeredUser = userRegistrationService.register(request);
    return ResponseEntity.status(HttpStatus.CREATED).body(UserResponse.from(registeredUser));
  }

  @PostMapping("/login")
  public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
    String token = authenticationService.login(request);
    return ResponseEntity.ok(new LoginResponse(token));
  }
}
