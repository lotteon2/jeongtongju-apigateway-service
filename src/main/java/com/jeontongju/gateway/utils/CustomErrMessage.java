package com.jeontongju.gateway.utils;

public interface CustomErrMessage {
    String NOT_VALID_JWT_TOKEN = "유효하지 않은 토큰입니다.";
    String WRONG_JWT_TOKEN = "잘못된 JWT 토큰입니다.";
    String MALFORMED_JWT_TOKEN = "변조된 JWT 토큰입니다.";
    String EXPIRED_JWT_TOKEN = "만료된 JWT 토큰입니다.";
    String WRONG_JWT_SIGNATURE = "잘못된 JWT 서명입니다.";
    String NO_AUTHORIZATION_HEADER = "헤더에 AUTHORIZATION 필드가 없습니다.";
    String NOT_MATCH_DOMAIN_ROLE = "해당 도메인과 역할이 맞지 않습니다.";
}
