package com.jwt.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "0sM3VP67x5gySbrg4AmP3rHv1gzGvDvr8tAJpItz9kZFJl+QIq9JA94J2w8xy/v6303qlIoYj9u1E6o4Ko1pTcFGv9Bb9zFu0SEcfVLs91+K7hohrL71HOq+73AsUDaZOz2qtZ29jLAwzgRs6hrQQ4mHAl56W+0VZN8S9bKt3ei58P+o4hYtcDGiFOPaetS/zqmtZtDRTnloFSbrX86sISYg0XlNziy2OJy0/K0zxYTwLFnLNWNDXXuORMvMkp97ZN3cKfPl2iiX4AVVlgcQUSD2xHAjFmtmAyysgPg+XPpvbup4N4DAschZXUuuex/+HyyDtwpyX2xx2xrZABR1H7XhYjjpjAIkk+php0YnH28=";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String  token, Function<Claims,T>claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object>extractClaims,
            UserDetails userDetails
    ) {

        return Jwts
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();

    }

    public boolean isTokenValid (String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date()); 
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

    }

    private Key getSignInKey() {

        byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
