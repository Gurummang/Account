package com.GASB.account.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

@Data
@AllArgsConstructor
public class LogInResponse implements Serializable {
    private final String jwt;
}
