package org.authorization.controller;

import lombok.RequiredArgsConstructor;
import org.authorization.model.response.AuthenticationRequest;
import org.authorization.model.response.AuthenticationResponse;
import org.authorization.model.response.RegisterRequest;
import org.authorization.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest registerRequest) {


        return ResponseEntity.ok(service.register(registerRequest));

    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest authenticationRequest) {


        return ResponseEntity.ok(service.authenticate(authenticationRequest));

    }
}
