package com.bowmeow.common.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;

public class JWTUtils {
    private final Key key;
    private static final long JWT_EXPIRATION_TIME = 3600000; // 1시간을 밀리초로 표현

    public JWTUtils() {
        String secretKey = System.getenv("JWT_SECRET_KEY"); // intellij에서 build 시에 지정한 환경변수의 jwt secret key를 가져옴
        if (secretKey == null || secretKey.isEmpty()) {
            throw new IllegalArgumentException("JWT_SECRET_KEY environment variable is empty");
        }
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    /**
     * jwt token 생성
     * - 로그인 시 user service 에서 호출
     * @param userId 유저 아이디
     * @return jwt token
     */
    public String generateToken(String userId) {
        return Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + JWT_EXPIRATION_TIME))
                .signWith(key)
                .compact();
    }

    public Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String extractUserId(String token) {
        return extractClaims(token).getSubject();
    }

    /**
     * jwt token validation 체크
     * - 각 서비스에서 validation 체크
     * @param token jwt 토큰
     * @return validation 여부
     */
    public boolean isTokenValid(String token) {
        try {
            extractClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}