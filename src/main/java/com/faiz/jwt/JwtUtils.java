package com.faiz.jwt;

import com.faiz.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;

@Component
public class JwtUtils {

    private static final long ACCESS_TOKEN_EXPIRATION = 10 * 60 * 1000; // 10 minutes
    private static final long REFRESH_TOKEN_EXPIRATION = 7 * 24 * 60 * 60 * 1000; // 7 days
    private static final String SECRET = "faizjwt7@@@@@@@@@@@@@777777777777777777777777777777777777";

    private Key getSecretKey() {
        return Keys.hmacShaKeyFor(SECRET.getBytes());
    }


    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", user.getRoles());
        return createToken(claims, user.getUsername(), ACCESS_TOKEN_EXPIRATION);
    }


    public String generateRefreshToken(User user) {
        return createToken(new HashMap<>(), user.getUsername(), REFRESH_TOKEN_EXPIRATION);
    }

    private String createToken(Map<String, Object> claims, String username, long expirationTime) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(getSecretKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    public Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSecretKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    public Set getRoles(String token) {
        return extractClaims(token).get("roles", Set.class);
    }


    public String getUsername(String token) {
        return extractClaims(token).getSubject();
    }


    public Date getExpirationDate(String token) {
        return extractClaims(token).getExpiration();
    }


    public boolean isTokenExpired(String token) {
        return getExpirationDate(token).before(new Date());
    }


    public boolean validateToken(String token, UserDetails userDetails) {
        return !isTokenExpired(token) && getUsername(token).equals(userDetails.getUsername());
    }


    public String refreshAccessToken(String refreshToken, UserDetails userDetails) {
        if (validateToken(refreshToken, userDetails)) {
            return generateAccessToken((User) userDetails);
        }
        return null;
    }
}