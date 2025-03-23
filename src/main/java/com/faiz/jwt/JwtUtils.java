package com.faiz.jwt;

import com.faiz.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.List;

@Component
public class JwtUtils {

    private static final Integer EXPIRATION_TIME = 10*60*60*60*60;

    private static final String SECRET = "faizjwt7@@@@@@@@@@@@@777777777777777777777777777777777777";

    public String generateToken(User user) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .claim("roles", user.getRoles())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis()+EXPIRATION_TIME))
                .signWith(getSecretKey(),SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSecretKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public List getRoles(String token) {
        Claims claims = extractClaims(token);
        return claims.get("roles", List.class);
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

    public Key getSecretKey(){
        return Keys.hmacShaKeyFor(SECRET.getBytes());
    }

}
