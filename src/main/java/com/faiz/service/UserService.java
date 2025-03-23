package com.faiz.service;

import com.faiz.bindings.LoginRequest;
import com.faiz.bindings.RegistrationRequest;
import com.faiz.entities.Role;
import com.faiz.entities.RoleType;
import com.faiz.entities.User;
import com.faiz.jwt.JwtUtils;
import com.faiz.repository.RoleRepository;
import com.faiz.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;
    private final RoleRepository roleRepository;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtils jwtUtils, AuthenticationManager authenticationManager, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
        this.authenticationManager = authenticationManager;
        this.roleRepository = roleRepository;
    }

    // Register user
    public Map<String, String> createUser(RegistrationRequest registrationRequest) {
        if (userRepository.findByUsername(registrationRequest.getUsername()).isPresent()) {
            throw new RuntimeException("Username is already in use");
        }

        // Fetch role
        Role role = roleRepository.findByName(RoleType.ROLE_USER);
        if (role == null) {
            role = new Role();
            role.setName(RoleType.ROLE_USER);
            role = roleRepository.save(role);
        }

        // Create user
        User user = new User();
        user.setUsername(registrationRequest.getUsername());
        user.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));
        user.setEmail(registrationRequest.getEmail());
        Set<Role> roles = new HashSet<>();
        roles.add(role);
        user.setRoles(roles);

        User savedUser = userRepository.save(user);

        // Generate tokens
        String accessToken = jwtUtils.generateAccessToken(savedUser);
        String refreshToken = jwtUtils.generateRefreshToken(savedUser);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);

        return tokens;
    }

    // Login user
    public Map<String, String> login(LoginRequest loginRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        User user = userRepository.findByUsername(loginRequest.getUsername())
                .orElseThrow(() -> new RuntimeException("Username not found"));

        // Generate tokens
        String accessToken = jwtUtils.generateAccessToken(user);
        String refreshToken = jwtUtils.generateRefreshToken(user);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);

        return tokens;
    }

    // Refresh token
    public Map<String, String> refreshToken(String refreshToken) {
        String username = jwtUtils.getUsername(refreshToken);

        if (username == null || jwtUtils.isTokenExpired(refreshToken)) {
            throw new RuntimeException("Invalid or expired refresh token");
        }

        Optional<User> optionalUser = userRepository.findByUsername(username);
        if (optionalUser.isEmpty()) {
            throw new RuntimeException("User not found");
        }

        User user = optionalUser.get();
        String newAccessToken = jwtUtils.generateAccessToken(user);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", newAccessToken);
        tokens.put("refresh_token", refreshToken);

        return tokens;
    }
}