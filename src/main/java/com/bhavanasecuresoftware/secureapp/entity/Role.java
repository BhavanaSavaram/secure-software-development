package com.bhavanasecuresoftware.secureapp.entity;

/**
 * The set of roles an AppUser can hold.
 *
 * Using an enum instead of a free-form String (the previous design) is a
 * best practice here: the compiler now rejects a typo like "ADMN" at
 * build time instead of silently creating a role that never matches any
 * @PreAuthorize / hasRole(...) check at runtime.
 */
public enum Role {

    // A normal, self-registered account. Can only view/manage its own
    // profile via GET /api/users/me.
    USER,

    // Elevated account. Can additionally look up any user by username via
    // GET /api/users/{username} (see UserController + SecurityConfig).
    ADMIN;

    /**
     * Spring Security's hasRole("X") / @PreAuthorize("hasRole('X')")
     * checks expect the authority string to be prefixed with "ROLE_"
     * (that prefix is stripped automatically when you write hasRole,
     * but the GrantedAuthority itself must carry it). Centralizing that
     * prefix here means it is defined in exactly one place instead of
     * being retyped as a raw string wherever a role is granted.
     */
    public String toSpringAuthority() {
        return "ROLE_" + name();
    }
}
