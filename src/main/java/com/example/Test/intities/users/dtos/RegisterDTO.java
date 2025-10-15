package com.example.Test.intities.users.dtos;

import com.example.Test.intities.users.UserRole;

public record RegisterDTO(String name, String email, String password, UserRole role) {
}
