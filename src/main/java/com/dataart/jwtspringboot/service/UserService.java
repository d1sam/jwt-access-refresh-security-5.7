package com.dataart.jwtspringboot.service;

import com.dataart.jwtspringboot.domain.Role;
import com.dataart.jwtspringboot.domain.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUsers();
}
