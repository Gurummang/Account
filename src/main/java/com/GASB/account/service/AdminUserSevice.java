package com.GASB.account.service;

import com.GASB.account.model.dto.UserRegistrationRequest;
import com.GASB.account.model.entity.AdminUsers;
import com.GASB.account.model.repository.AdminUserRepo;
import com.GASB.account.model.repository.OrgRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AdminUserSevice {

    private final AdminUserRepo adminUserRepository;
    private final OrgRepo orgRepository;
    private final PasswordEncoder passwordEncoder;

    public void registerAdmin(UserRegistrationRequest request) {

        if (adminUserRepository.findByEmail(request.getEmail()) != null) {
            throw new RuntimeException("User already exists");
        }

        AdminUsers adminUsers = AdminUsers.builder()
                .org(orgRepository.findById(request.getOrgId()).orElse(null))
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .build();

        adminUserRepository.save(adminUsers);
    }
}
