package com.trek.summitBase.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class TokenStore {

    private final StringRedisTemplate redis;

    public void saveRefreshToken(String userId, String token) {
        redis.opsForValue().set("refresh:" + userId, token, Duration.ofDays(7));
    }

    public boolean isRefreshTokenValid(String userId, String token) {
        String stored = redis.opsForValue().get("refresh:" + userId);
        return stored != null && stored.equals(token);
    }

    public void blacklistToken(String jti, Duration ttl) {
        if (ttl.isNegative()) return;
        redis.opsForValue().set("blacklist:" + jti, "1", ttl);
    }

    public boolean isBlacklisted(String jti) {
        return Boolean.TRUE.equals(redis.hasKey("blacklist:" + jti));
    }

    public void deleteRefreshToken(String userId) {
        redis.delete("refresh:" + userId);
    }
}
