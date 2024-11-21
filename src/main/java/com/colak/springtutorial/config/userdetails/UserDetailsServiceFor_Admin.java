package com.colak.springtutorial.config.userdetails;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@RequiredArgsConstructor
public class UserDetailsServiceFor_Admin implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        if (username.equals("admin")) {
            String password = passwordEncoder.encode("123456");
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ADMIN");
            return new User(username, password, List.of(authority));
        } else {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
    }
}
