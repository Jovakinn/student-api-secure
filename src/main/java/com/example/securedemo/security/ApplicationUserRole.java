package com.example.securedemo.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;

import static com.example.securedemo.security.ApplicationUserPermission.COURSE_READ;
import static com.example.securedemo.security.ApplicationUserPermission.COURSE_WRITE;
import static com.example.securedemo.security.ApplicationUserPermission.STUDENT_READ;
import static com.example.securedemo.security.ApplicationUserPermission.STUDENT_WRITE;
import static java.util.stream.Collectors.toSet;

public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ));

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
        var permissionsGranted = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(toSet());
        permissionsGranted.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permissionsGranted;
    }
}
