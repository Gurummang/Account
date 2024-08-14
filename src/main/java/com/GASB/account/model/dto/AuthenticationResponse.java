package com.GASB.account.model.dto;

import lombok.*;

import java.io.Serializable;

@Data
@AllArgsConstructor
public class AuthenticationResponse implements Serializable {
    private final String email;
    private final String status;
}
