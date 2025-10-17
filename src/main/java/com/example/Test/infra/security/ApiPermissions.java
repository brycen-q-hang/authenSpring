package com.example.Test.infra.security;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ApiPermissions {
    public static final List<String> ADMIN_PATHS = Arrays.asList(
            "admin/get_admin", "admin/config_admin", "admin/only_post_admin");

    public static final List<String> USER_PATHS = Arrays.asList(
            "user/get_user", "user/config_user");

    public static final Map<String, List<String>> PERMISSIONS_MAP = new HashMap<>();

    static {
        PERMISSIONS_MAP.put("ROLE_ADMIN", ADMIN_PATHS);
        PERMISSIONS_MAP.put("ROLE_USER", USER_PATHS);
    }

    public static boolean isAdminPath(String path) {
        return ADMIN_PATHS.contains(path);
    }

    private ApiPermissions() {
    }
}