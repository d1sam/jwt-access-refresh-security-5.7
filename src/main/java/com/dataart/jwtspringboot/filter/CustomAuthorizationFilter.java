package com.dataart.jwtspringboot.filter;

import com.dataart.jwtspringboot.handlers.SecurityExceptionsHandler;
import com.dataart.jwtspringboot.jwt.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.dataart.jwtspringboot.util.StringUtils.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    private final TokenService tokenService;
    private final SecurityExceptionsHandler securityExceptionsHandler;

    public CustomAuthorizationFilter(TokenService tokenService, SecurityExceptionsHandler securityExceptionsHandler) {
        this.securityExceptionsHandler = securityExceptionsHandler;
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals(LOGIN_URL) || request.getServletPath().equals(TOKEN_REFRESH_URL)) {
            filterChain.doFilter(request, response);
        } else {
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            if (authorizationHeader != null && authorizationHeader.startsWith(JWT_PREFIX)) {
                try {
                    String token = authorizationHeader.substring(JWT_PREFIX.length());
                    UsernamePasswordAuthenticationToken authenticationToken = tokenService.decodeAccessToken(token);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request, response);
                } catch (Exception e) {
                    securityExceptionsHandler.handleSecurityException(e.getMessage(), response);
                }
            } else {
                filterChain.doFilter(request, response);
            }
        }
    }
}
