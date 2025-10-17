package com.example.Test.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(produces = { "application/json" })
public class TestController {

    @GetMapping("admin/get_admin")
    public ResponseEntity<String> adminApi1() {
        return ResponseEntity.ok("");
    }

    @GetMapping("admin/config_admin")
    public ResponseEntity<String> adminApi2() {
        return ResponseEntity.ok("");
    }

    @PostMapping("admin/only_post_admin")
    public ResponseEntity<String> adminApi3() {
        return ResponseEntity.ok("");
    }

    @GetMapping("user/get_user")
    public ResponseEntity<String> userApi1() {
        return ResponseEntity.ok("");
    }

    @GetMapping("user/config_user")
    public ResponseEntity<String> userApi2() {
        return ResponseEntity.ok("");
    }

    @GetMapping("/authenticated-only")
    public ResponseEntity<String> authenticatedApi() {
        return ResponseEntity.ok("");
    }
}