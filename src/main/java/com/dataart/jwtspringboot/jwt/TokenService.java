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

    private final Date expirationDateOfAccessToken
            // current time + 60 mins * 60 secs * 1000 msecs
            = new Date(System.currentTimeMillis() + 60 * 60 * 1000);

    private final Date expirationDateOfRefreshToken
            // current time + 30 days + 24 hours + 60 mins * 60 secs * 1000 msecs
            = new Date(System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000);

    public UsernamePasswordAuthenticationToken decodeAccessToken(String token) {
        DecodedJWT decodedJWT = getDecodedJWTFromToken(token);
        String username = decodedJWT.getSubject();
        String[] roles = decodedJWT.getClaim(ROLES_CLAIM).asArray(String.class);
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        stream(roles).forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, null, authorities);
        return authenticationToken;
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
                .withExpiresAt(expirationDateOfAccessToken)
                .withIssuer(issuer)
                .withClaim(ROLES_CLAIM, user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(getAlgorithm());
    }

    public String generateRefreshToken(String issuer, User user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(expirationDateOfRefreshToken)
                .withIssuer(issuer)
                .sign(getAlgorithm());
    }

    public String generateAccessTokenForUserFromDB(String issuer, com.dataart.jwtspringboot.domain.User user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(expirationDateOfAccessToken)
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
}
