package com.GASB.account.service;

import com.GASB.account.model.entity.AdminUsers;
import com.GASB.account.model.repository.AdminUserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.ArrayList;

@Service
@RequiredArgsConstructor
public class MyUserDetailsService implements UserDetailsService {

    private final AdminUserRepo adminUserRepo;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        AdminUsers adminUsers = adminUserRepo.findByEmail(email);
        if(adminUserRepo == null){
            throw new UsernameNotFoundException("User not found");
        }
        return new org.springframework.security.core.userdetails.User(adminUsers.getEmail(), adminUsers.getPassword(), new ArrayList<>());
    }
}
