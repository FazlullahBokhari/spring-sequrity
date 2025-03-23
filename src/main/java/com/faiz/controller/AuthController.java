package com.faiz.controller;

import com.faiz.bindings.LoginRequest;
import com.faiz.bindings.LoginResponse;
import com.faiz.bindings.RegistrationRequest;
import com.faiz.entities.User;
import com.faiz.jwt.JwtUtils;
import com.faiz.service.UserService;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.List;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserService userService;


    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegistrationRequest request) {
        String token = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(token);
    }


    @GetMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest request) {
        String token = userService.login(request);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }


}
