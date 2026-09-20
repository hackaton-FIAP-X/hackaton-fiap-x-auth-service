package br.com.fiap.hackaton.auth.user;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.fiap.hackaton.auth.web.ErrorResponse;
import br.com.fiap.hackaton.auth.web.ValidationErrorResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
@Tag(name = "Autenticacao", description = "Registro de usuarios e emissao de tokens JWT")
public class AuthController {

  private final UserRegistrationService userRegistrationService;
  private final AuthenticationService authenticationService;

  public AuthController(
      UserRegistrationService userRegistrationService,
      AuthenticationService authenticationService) {
    this.userRegistrationService = userRegistrationService;
    this.authenticationService = authenticationService;
  }

  @Operation(summary = "Registra um novo usuario")
  @ApiResponse(responseCode = "201", description = "Usuario criado com sucesso")
  @ApiResponse(
      responseCode = "400",
      description = "Dados de registro invalidos",
      content = @Content(schema = @Schema(implementation = ValidationErrorResponse.class)))
  @ApiResponse(
      responseCode = "409",
      description = "E-mail ja cadastrado",
      content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
  @PostMapping("/register")
  public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
    User registeredUser = userRegistrationService.register(request);
    return ResponseEntity.status(HttpStatus.CREATED).body(UserResponse.from(registeredUser));
  }

  @Operation(summary = "Autentica um usuario e emite um token JWT RS256")
  @ApiResponse(responseCode = "200", description = "Login realizado com sucesso")
  @ApiResponse(
      responseCode = "400",
      description = "Dados de login invalidos",
      content = @Content(schema = @Schema(implementation = ValidationErrorResponse.class)))
  @ApiResponse(
      responseCode = "401",
      description = "Credenciais invalidas",
      content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
  @ApiResponse(responseCode = "429", description = "Limite de tentativas de login excedido")
  @PostMapping("/login")
  public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
    String token = authenticationService.login(request);
    return ResponseEntity.ok(new LoginResponse(token));
  }
}
