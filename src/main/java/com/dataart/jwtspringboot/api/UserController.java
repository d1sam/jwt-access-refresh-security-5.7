package com.dataart.jwtspringboot.api;

import com.dataart.jwtspringboot.domain.Role;
import com.dataart.jwtspringboot.domain.User;
import com.dataart.jwtspringboot.handlers.SecurityExceptionsHandler;
import com.dataart.jwtspringboot.jwt.TokenService;
import com.dataart.jwtspringboot.service.UserService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.List;

import static com.dataart.jwtspringboot.util.StringUtils.JWT_PREFIX;
import static com.dataart.jwtspringboot.util.StringUtils.TOKEN_REFRESH_URL;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {
    private final UserService userService;
    private final TokenService tokenService;
    private final SecurityExceptionsHandler securityExceptionsHandler;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers() {
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @PostMapping("/user/save")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        URI uri = URI.create(ServletUriComponentsBuilder
                .fromCurrentContextPath()
                .path("/api/user/save")
                .toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder
                .fromCurrentContextPath()
                .path("/api/role/save")
                .toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/role/addToUser")
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserFrom form) {
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }

    @PostMapping(TOKEN_REFRESH_URL)
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith(JWT_PREFIX)) {
            try {
                String refreshToken = authorizationHeader.substring(JWT_PREFIX.length());
                String accessToken = tokenService.verifyRefreshAndGetNewAccessToken(refreshToken, request.getRequestURL().toString());
                tokenService.writeTokensToResponse(response, accessToken, refreshToken);
            } catch (Exception e) {
                securityExceptionsHandler.handleSecurityException(e.getMessage(), response);
            }
        } else {
            throw new RuntimeException();
        }
    }
}

@Data
class RoleToUserFrom {
    private String username;
    private String roleName;
}
