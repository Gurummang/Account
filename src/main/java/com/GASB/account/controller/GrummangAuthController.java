package com.GASB.account.controller;


import com.GASB.account.component.EmailValidator;
import com.GASB.account.component.JwtUtil;
import com.GASB.account.component.PasswordValidator;
import com.GASB.account.model.dto.*;
import com.GASB.account.model.entity.AdminUsers;
import com.GASB.account.model.repository.AdminUserRepo;
import com.GASB.account.service.AdminUserSevice;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class GrummangAuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final AdminUserSevice adminUserService;
    private final AdminUserRepo adminUserRepo;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> registerUser(@RequestBody UserRegistrationRequest request) {
        try {
            String email = request.getEmail();
            String pw = request.getPassword();

            if (email == null || !EmailValidator.isValid(email) || pw == null || !PasswordValidator.isValid(pw)) {
                return ResponseEntity.badRequest().body(new RegisterResponse("error", "Email and password must be provided and valid"));
            }

            if (adminUserRepo.existsByEmail(email)) {
                return ResponseEntity.badRequest().body(new RegisterResponse("error", "User already exists"));
            }

            adminUserService.registerAdmin(request);
            return ResponseEntity.ok(new RegisterResponse("success", "User registered successfully"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new RegisterResponse("error", "An error occurred during registration"));
        }
    }


    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest, HttpServletResponse response) throws Exception {
        Map<String,String> responseMap = new HashMap<>();
        try {
            // DB에서 사용자 정보 및 솔트 가져오기
            AdminUsers adminUser = adminUserRepo.findByEmail(authenticationRequest.getEmail());

            if (adminUser == null) {
                throw new BadCredentialsException("Incorrect username or password");
            }

            // 입력된 비밀번호와 솔트를 결합하여 인증 시도
            String saltedPassword = adminUser.getSalt() + authenticationRequest.getPassword();
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getEmail(), saltedPassword));
        } catch (BadCredentialsException e) {
            responseMap.put("status", "error");
            responseMap.put("message", "Incorrect username or password");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseMap);
        } catch (Exception e) {
            responseMap.put("status", "error");
            responseMap.put("message", "An error occurred during authentication");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseMap);
        }

        // 사용자 인증 성공 후 JWT 생성
        final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getEmail());
        final String jwt = jwtUtil.generateToken(userDetails.getUsername());
        // JWT를 HttpOnly 쿠키에 저장
        Cookie cookie = new Cookie("jwt", jwt);
        cookie.setHttpOnly(true);
        cookie.setAttribute("SameSite", "None");
        cookie.setSecure(true); // HTTPS를 사용할 때만 활성화
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60 ); // 1시간


        response.addCookie(cookie);

        adminUserRepo.setLastLoginTimeByEmail(authenticationRequest.getEmail());
        responseMap.put("status", "success");
        responseMap.put("jwt", jwt);
        return ResponseEntity.ok(responseMap);
    }



    @PostMapping("/validate")
    public ResponseEntity<AuthenticationResponse> validateToken(@RequestHeader("Authorization") String authorizationHeader) {
        try{
            if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(401).body(new AuthenticationResponse(null, "Invalid token"));
            }
            String token = authorizationHeader.substring(7); // Remove "Bearer " prefix
            if (jwtUtil.validateToken(token)) {
                String email = jwtUtil.extractUserEmail(token);
                return ResponseEntity.ok(new AuthenticationResponse(email, "OK"));
            } else {
                return ResponseEntity.status(401).body(new AuthenticationResponse(null, "Invalid token"));
            }

        } catch (Exception e) {
            return ResponseEntity.status(401).body(new AuthenticationResponse(null, "Invalid token"));
        }
    }

    @GetMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("jwt", "");
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        return ResponseEntity.ok().build();
    }
}
