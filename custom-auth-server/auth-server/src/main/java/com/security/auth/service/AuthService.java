package com.security.auth.service;

import com.security.auth.dto.request.AuthRequest;
import com.security.auth.dto.request.RefreshTokenRequestDto;
import com.security.auth.dto.request.RegisterRequest;
import com.security.auth.dto.response.TokenResponse;
import com.security.auth.entity.EnumRole;
import com.security.auth.entity.RefreshToken;
import com.security.auth.entity.Role;
import com.security.auth.entity.User;
import com.security.auth.exception.InvalidTokenException;
import com.security.auth.repository.RoleRepository;
import com.security.auth.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class AuthService {

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public AuthService(JwtService jwtService, RefreshTokenService refreshTokenService, AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, UserRepository userRepository, RoleRepository roleRepository) {
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }


    public TokenResponse register(RegisterRequest authRequest) {

        User user = new User();
        user.setUsername(authRequest.username());
        user.setPassword(passwordEncoder.encode(authRequest.password()));

        Role userRole = roleRepository.findByAuthority(EnumRole.USER)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));

        user.setRoles(List.of(userRole));
        userRepository.save(user);

        String accessToken = jwtService.generateToken(authRequest.username(), List.of(EnumRole.USER.name()));
        RefreshToken refreshToken = jwtService.generateRefreshToken(user);
        return new TokenResponse(accessToken, refreshToken.getToken());
    }

    public TokenResponse login(AuthRequest authRequest) {
        Authentication auth =
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.username(), authRequest.password()));

        if (auth.isAuthenticated()) {
            List<String> roles = auth.getAuthorities().stream().map(x -> x.getAuthority()).collect(Collectors.toUnmodifiableList());
            String accessToken = jwtService.generateToken(authRequest.username(), roles);

            User user = (User) auth.getPrincipal();
            RefreshToken refreshToken = jwtService.generateRefreshToken(user);

            return new TokenResponse(accessToken, refreshToken.getToken());
        }

        throw new UsernameNotFoundException("Invalid username or password");
    }

    public TokenResponse refreshToken(RefreshTokenRequestDto refreshTokenRequest) {

        RefreshToken refreshToken = refreshTokenService.refreshTokenLogin(refreshTokenRequest);
        User user = refreshToken.getUser();

        List<String> roleList = user.getRoles().stream().map(role -> role.toString()).collect(Collectors.toList());
        String accessToken = jwtService.generateToken(user.getUsername(), roleList);

        return new TokenResponse(accessToken, refreshToken.getToken());

    }

    public String validate(String token) {

        if (jwtService.validateToken(token)) {
            return "Token is valid";
        }

        throw new InvalidTokenException("Invalid token");
    }

    public String getPublicKey() {
        PublicKey publicKey = jwtService.getPublicKey();
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

}
