package com.security.jwt.config;

import com.security.jwt.jwt.JwtAccessDeniedHandler;
import com.security.jwt.jwt.JwtAuthenticationEntryPoint;
import com.security.jwt.jwt.JwtSecurityConfig;
import com.security.jwt.jwt.TokenProvider;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.filter.CorsFilter;

@EnableWebSecurity
@EnableMethodSecurity
@Configuration
//@ComponentScan(basePackages={"org.springframework.web.filter.CorsFilter", "com.security.jwt.config"})
public class SecurityConfig {
    private final TokenProvider tokenProvider;

    //private final CorsFilter corsFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(
            TokenProvider tokenProvider,
    //        CorsFilter corsFilter,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
    //    this.corsFilter = corsFilter;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests()
                .antMatchers("/api/**").permitAll()
                .antMatchers("/auth/**").permitAll()
                .antMatchers("/**").permitAll()
                .anyRequest().authenticated();
        http.exceptionHandling(exceptionHandling -> exceptionHandling
                        .accessDeniedHandler(jwtAccessDeniedHandler)
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                );
        http.apply(new JwtSecurityConfig(tokenProvider));
        return http.build();
//        http
//                // token을 사용하는 방식이기 때문에 csrf를 disable합니다.
//                //.csrf(csrf -> csrf.disable())
//                .csrf()
//                .disable()
//
//                //.addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
//                .exceptionHandling(exceptionHandling -> exceptionHandling
//                        .accessDeniedHandler(jwtAccessDeniedHandler)
//                        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
//                )
//
//                // 세션을 사용하지 않기 때문에 STATELESS로 설정
//                .sessionManagement(sessionManagement ->
//                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                )
////                .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
////                        //.requestMatchers("/api/hello", "/api/authenticate", "/api/signup").permitAll()
////                        //.requestMatchers(HttpMethod.POST, "/api/hello").permitAll()
////                        .antMatchers("/api/hello").permitAll()
////                        .antMatchers("/api/authenticate").permitAll()
////                        .antMatchers("/api/signup").permitAll()
////                        .antMatchers("/api/**").permitAll()
////                        .antMatchers("/**").permitAll()
////                        //.antMatchers("/api/signup").permitAll()
////                        //.requestMatchers()
////                        //.requestMatchers(PathRequest.toH2Console()).permitAll()
////                        .anyRequest().authenticated() // 이외의 모든 요청은 인증된 사용자만 접근 가능
////                )
//                .authorizeHttpRequests()
//                //.antMatchers("/api/hello").permitAll()
//                //.antMatchers("/api/authenticate").permitAll()
//                .antMatchers("/api/signup").permitAll()
//                .antMatchers("/api/**").permitAll()
//                .antMatchers("/**").permitAll()
//                .anyRequest().authenticated()
//                .and()
//
//                // enable h2-console
////                .headers(headers ->
////                        headers.frameOptions(options ->
////                                options.sameOrigin()
////                        )
////                )
//
//                .apply(new JwtSecurityConfig(tokenProvider));
//        return http.build();
    }
}