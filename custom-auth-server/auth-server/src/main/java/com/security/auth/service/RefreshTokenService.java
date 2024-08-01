package com.security.auth.service;


import com.security.auth.dto.request.RefreshTokenRequestDto;
import com.security.auth.entity.RefreshToken;
import com.security.auth.entity.User;
import com.security.auth.exception.InvalidTokenException;
import com.security.auth.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Value("${jwt.refresh-token.expire.time}")
    private Long REFRESH_TOKEN_EXPIRATION;

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public RefreshToken generateRefreshToken(User user) {

        var existsToken = refreshTokenRepository.findByUserId(user.getId());
        if (existsToken.isPresent())
            refreshTokenRepository.delete(existsToken.get());

        var refreshToken = UUID.randomUUID().toString();
        var refreshTokenEntity = RefreshToken.builder().token(refreshToken)
                .expiration(ZonedDateTime.now().plusMinutes(REFRESH_TOKEN_EXPIRATION))
                .user(user).build();
        refreshTokenRepository.save(refreshTokenEntity);

        return refreshTokenEntity;
    }

    public RefreshToken refreshTokenLogin(RefreshTokenRequestDto refreshTokenRequestDto) {
        var refreshToken = refreshTokenRepository.findByToken(refreshTokenRequestDto.refreshToken())
                .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

        refreshTokenRepository.delete(refreshToken);
        if (isTokenExpired(refreshToken.getExpiration()))
            throw new InvalidTokenException("Refresh token not found");

        return generateRefreshToken(refreshToken.getUser());

    }

    private boolean isTokenExpired(ZonedDateTime expirationTime) {
        return expirationTime.isBefore(ZonedDateTime.now(ZoneId.systemDefault()));
    }

}
