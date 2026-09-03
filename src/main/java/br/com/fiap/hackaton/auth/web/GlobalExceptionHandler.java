package br.com.fiap.hackaton.auth.web;

import br.com.fiap.hackaton.auth.user.EmailAlreadyRegisteredException;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(EmailAlreadyRegisteredException.class)
  public ResponseEntity<ErrorResponse> handleEmailAlreadyRegistered(
      EmailAlreadyRegisteredException ex) {
    return ResponseEntity.status(HttpStatus.CONFLICT).body(new ErrorResponse(ex.getMessage()));
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ValidationErrorResponse> handleValidation(
      MethodArgumentNotValidException ex) {
    List<ValidationErrorResponse.FieldErrorDetail> fieldErrors =
        ex.getBindingResult().getFieldErrors().stream()
            .map(
                error ->
                    new ValidationErrorResponse.FieldErrorDetail(
                        error.getField(), error.getDefaultMessage()))
            .toList();
    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
        .body(new ValidationErrorResponse("Validation failed", fieldErrors));
  }
}
