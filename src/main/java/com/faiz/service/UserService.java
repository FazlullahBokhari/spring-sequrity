package com.faiz.service;

import com.faiz.bindings.LoginRequest;
import com.faiz.bindings.RegistrationRequest;
import com.faiz.entities.Role;
import com.faiz.entities.RoleType;
import com.faiz.entities.User;
import com.faiz.jwt.JwtUtils;
import com.faiz.repository.RoleRepository;
import com.faiz.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
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


    public String createUser(RegistrationRequest registrationRequest) {
        if(userRepository.findByUsername(registrationRequest.getUsername()).isPresent()){
            throw new RuntimeException("Username is already in use");
        }

        Role role = roleRepository.findByName(RoleType.ROLE_USER);
        if (role == null) {
            role = new Role();
            role.setName(RoleType.ROLE_USER);
            role = roleRepository.save(role);
        }

        User user = new User();
        user.setUsername(registrationRequest.getUsername());
        user.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));
        user.setEmail(registrationRequest.getEmail());
        Set<Role> roles = new HashSet<>();
        roles.add(role);
        user.setRoles(roles);

        User savedUser = userRepository.save(user);

        return jwtUtils.generateToken(savedUser);
    }

    public String login(LoginRequest loginRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        User user = userRepository.findByUsername(loginRequest.getUsername())
                .orElseThrow(() -> new RuntimeException("Username not found"));
        return jwtUtils.generateToken(user);
    }
}
