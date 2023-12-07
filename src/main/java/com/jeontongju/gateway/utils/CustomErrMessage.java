package com.jeontongju.gateway.utils;

public interface CustomErrMessage {
    final String NOT_VALID_JWT_TOKEN = "유효하지 않은 토큰입니다.";
    final String WRONG_JWT_TOKEN = "잘못된 JWT 토큰입니다.";
    final String MALFORMED_JWT_TOKEN = "변조된 JWT 토큰입니다.";
    final String EXPIRED_JWT_TOKEN = "만료된 JWT 토큰입니다.";
    final String WRONG_JWT_SIGNATURE = "잘못된 JWT 서명입니다.";
    final String NO_AUTHORIZATION_HEADER = "헤더에 AUTHORIZATION 필드가 없습니다.";
}
