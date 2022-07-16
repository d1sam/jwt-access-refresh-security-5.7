package com.dataart.jwtspringboot.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.dataart.jwtspringboot.domain.Role;
import com.dataart.jwtspringboot.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Service
@RequiredArgsConstructor
public class TokenService {
    @Value("${spring.security.secret.jwt.sign}")
    private String secretSign;

    private final UserService userService;

    private static final String ROLES_CLAIM = "roles";

    // 60 minutes
    private static final long HOUR = 60 * 60 * 1000;

    // 30 days
    private static final long MONTH = 30L * 24 * 60 * 60 * 1000;

    public UsernamePasswordAuthenticationToken decodeAccessToken(String token) {
        DecodedJWT decodedJWT = getDecodedJWTFromToken(token);
        String username = decodedJWT.getSubject();
        String[] roles = decodedJWT.getClaim(ROLES_CLAIM).asArray(String.class);
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        stream(roles).forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));
        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }

    public String verifyRefreshAndGetNewAccessToken(String refreshToken, String issuer) {
        DecodedJWT decodedJWT = getDecodedJWTFromToken(refreshToken);
        String username = decodedJWT.getSubject();
        com.dataart.jwtspringboot.domain.User user = userService.getUser(username);
        return generateAccessTokenForUserFromDB(issuer, user);
    }

    public String generateAccessTokenForUserFromSecurityContextHolder(String issuer, User user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(getExpirationDateOfToken(HOUR))
                .withIssuer(issuer)
                .withClaim(ROLES_CLAIM, user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(getAlgorithm());
    }

    public String generateRefreshToken(String issuer, User user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(getExpirationDateOfToken(MONTH))
                .withIssuer(issuer)
                .sign(getAlgorithm());
    }

    public String generateAccessTokenForUserFromDB(String issuer, com.dataart.jwtspringboot.domain.User user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(getExpirationDateOfToken(HOUR))
                .withIssuer(issuer)
                .withClaim(ROLES_CLAIM, user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                .sign(getAlgorithm());
    }

    public void writeTokensToResponse(HttpServletResponse response, String accessToken, String refreshToken) throws IOException {
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);

        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }

    private Algorithm getAlgorithm() {
        return Algorithm.HMAC256(secretSign);
    }

    private DecodedJWT getDecodedJWTFromToken(String token) {
        JWTVerifier jwtVerifier = JWT.require(getAlgorithm()).build();
        return jwtVerifier.verify(token);
    }

    private Date getExpirationDateOfToken(long time) {
        return new Date(System.currentTimeMillis() + time);
    }
}
