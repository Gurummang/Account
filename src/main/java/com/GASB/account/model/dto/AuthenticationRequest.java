package com.GASB.account.model.dto;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;

import java.io.Serializable;

@Data
public class AuthenticationRequest implements Serializable {
    private String email;
    private String password;
}
