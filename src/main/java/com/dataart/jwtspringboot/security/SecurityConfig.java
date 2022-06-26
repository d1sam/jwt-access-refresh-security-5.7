package com.dataart.jwtspringboot.security;

import com.dataart.jwtspringboot.filter.CustomAuthenticationFilter;
import com.dataart.jwtspringboot.filter.CustomAuthorizationFilter;
import com.dataart.jwtspringboot.handlers.SecurityExceptionsHandler;
import com.dataart.jwtspringboot.jwt.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static com.dataart.jwtspringboot.util.StringUtils.LOGIN_URL;
import static com.dataart.jwtspringboot.util.StringUtils.TOKEN_REFRESH_URL;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    private final AuthenticationConfiguration authenticationConfiguration;
    private final TokenService tokenService;
    private final SecurityExceptionsHandler securityExceptionsHandler;

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManager(), tokenService);
        customAuthenticationFilter.setFilterProcessesUrl(LOGIN_URL);
        http.csrf().disable().cors().disable();
        http.sessionManagement().sessionCreationPolicy(STATELESS);
        http.authorizeRequests().antMatchers(LOGIN_URL + "/**", TOKEN_REFRESH_URL + "/**").permitAll();
        http.authorizeRequests().antMatchers(GET, "/api/user/**").hasAnyAuthority("ROLE_USER");
        http.authorizeRequests().antMatchers(POST, "/api/user/save/**").hasAnyAuthority("ROLE_ADMIN");
        http.authorizeRequests().anyRequest().authenticated();
        http.addFilter(customAuthenticationFilter);
        http.addFilterBefore(new CustomAuthorizationFilter(tokenService, securityExceptionsHandler), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
