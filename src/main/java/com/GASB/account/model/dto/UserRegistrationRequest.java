package com.GASB.account.model.dto;

import lombok.Data;

@Data
public class UserRegistrationRequest {
//    private Long orgId;
    private String email;
    private String password;
    private String firstName;
    private String lastName;
}
