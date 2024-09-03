package com.bowmeow.common.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;

public class JWTUtils {
    /* [common project 라이브러리화 및 다른 프로젝트에서 사용방법]
     * 1. 현재 프로젝트에서 ./gradlew publishToMavenLocal 명령어를 통해 로컬 Maven 리포지토리에 JAR을 배포
     * 2. project tab 에서 build > libs 에 만들어진 jar 파일 확인
     * 3. 사용할 다른 프로젝트에 gradle에 아래 내용 추가
       repositories {
            mavenLocal()
            mavenCentral()
       }
        dependencies {
            implementation 'com.bowmeow:bowmeow-common:1.0.0' // 2번에서 확인한 jar 파일명
        }
     * 4. JWTService 구현하여 사용
     */


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