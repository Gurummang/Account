package com.GASB.account.service;

import com.GASB.account.model.dto.UserRegistrationRequest;
import com.GASB.account.model.entity.AdminUsers;
import com.GASB.account.model.repository.AdminUserRepo;
import com.GASB.account.model.repository.OrgRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class AdminUserSevice {

    private final AdminUserRepo adminUserRepository;
    private final OrgRepo orgRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${grummang.org.id}")
    private Long orgId;

    private static final int SALT_LENGTH = 16;

    public void registerAdmin(UserRegistrationRequest request) {

        if (adminUserRepository.findByEmail(request.getEmail()) != null) {
            throw new RuntimeException("User already exists");
        }

        // 솔트 생성
        String salt = generateSalt();

        // 솔트와 비밀번호를 결합하여 해싱
        String saltedPassword = salt + request.getPassword();
        String hashedPassword = passwordEncoder.encode(saltedPassword);

        // AdminUsers 엔티티에 솔트와 해시된 비밀번호를 저장
        AdminUsers adminUsers = AdminUsers.builder()
                .org(orgRepository.findById(orgId).orElse(null))
                .email(request.getEmail())
                .password(hashedPassword)
                .salt(salt) // 솔트를 저장
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .build();

        adminUserRepository.save(adminUsers);
    }



    private String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH]; // 16바이트 길이의 솔트
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }
}
