package org.example.liquoriceauthenticationserver.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Object> handleIllegalArgumentException(IllegalArgumentException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("message", "Invalid arguments passed: " + ex.getMessage());
        body.put("error", ex.getClass().getSimpleName());

        return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
    }
}
