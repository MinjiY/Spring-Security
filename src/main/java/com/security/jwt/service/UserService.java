package com.security.jwt.service;

import com.security.jwt.dto.UserDto;
import com.security.jwt.entity.Authority;
import com.security.jwt.entity.User;
import com.security.jwt.repository.UserRepository;
import com.security.jwt.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // UserService 클래스는 UserRepository, PasswordEncoder를 주입받는다.
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // username이 DB에 존재하지 않으면 Authority와 User정보를 생성해서 UserRepository의 save메서드를 통해 DB에 정보를 저장한다.
    @Transactional
    public UserDto signup(UserDto userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        // 권한 정보 생성
        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        // 생성한 권한 정보 넣어서 유저를 생성
        // 여기서 중요한 것은 signUp 메서드를 통해 가입한 회원은 USER ROLE을 가지고 있고 data.sql을 통해 자동 생성되는 admin 계정은
        // ROLE_USER, ROLE_ADMIN 을 가지고 있다.
        // 이 차이를 통해 권한검증 부분을 테스트
        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();


        return UserDto.from(userRepository.save(user));
    }

    // username을 기준으로 정보를 가져오고
    @Transactional(readOnly = true)
    public UserDto getUserWithAuthorities(String username) {
        return UserDto.from(userRepository.findOneWithAuthoritiesByUsername(username).orElse(null));
    }

    // getMyUserWithAuthorities는 SecurityContext에 저장된 username의 정보만 가져온다.
    // 두가지 메서드의 허용 권한을 다르게 해서 권한 검증을 테스트
    @Transactional(readOnly = true)
    public UserDto getMyUserWithAuthorities() {
        return UserDto.from(
                SecurityUtil.getCurrentUsername()
                        .flatMap(userRepository::findOneWithAuthoritiesByUsername)
                        .orElseThrow(() -> new RuntimeException("Member not found"))
        );
    }
}
