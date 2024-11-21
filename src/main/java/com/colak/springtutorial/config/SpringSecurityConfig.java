package com.colak.springtutorial.config;

import com.colak.springtutorial.config.authenticationsuccesshandler.CustomAuthenticationSuccessHandler;
import com.colak.springtutorial.config.userdetails.UserDetailsServiceFor_Admin;
import com.colak.springtutorial.config.userdetails.UserDetailsServiceFor_User;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SpringSecurityConfig {

    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Bean
    public UserDetailsService userDetailsService_User1() {
        return new UserDetailsServiceFor_Admin((BCryptPasswordEncoder) passwordEncoder());
    }

    @Bean
    public UserDetailsService userDetailsService_User2() {
        return new UserDetailsServiceFor_User(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http
                .getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder
                .userDetailsService(userDetailsService_User1())
                .passwordEncoder(passwordEncoder());

        authenticationManagerBuilder
                .userDetailsService(userDetailsService_User2())
                .passwordEncoder(passwordEncoder());

        return authenticationManagerBuilder.build();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                        // RBAC Urls
                        // admin can access AdminController
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        // user can access UserController
                        .requestMatchers("/user/**").hasRole("USER")
                        // everybody can access PublicController
                        .requestMatchers("/public/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(login -> login
                        .successHandler(customAuthenticationSuccessHandler)
                        .permitAll()
                )
                .logout(LogoutConfigurer::permitAll);
        return http.build();
    }


}
