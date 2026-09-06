package com.bhavanasecuresoftware.secureapp.dto;

import com.bhavanasecuresoftware.secureapp.entity.AppUser;

/**
 * The JSON shape returned by the /api/users/** endpoints.
 *
 * A Java "record" is a compact way to declare an immutable data holder --
 * the compiler generates the constructor, getters (id(), username(), ...),
 * equals/hashCode, and toString automatically from the field list below.
 *
 * This is deliberately a SEPARATE type from AppUser (the entity), and the
 * controller always converts AppUser -> UserSummary before returning a
 * response. That conversion is what guarantees hashedPassword can never
 * leak into an HTTP response body, even if a future change adds more
 * sensitive fields to AppUser -- they would need to be explicitly added
 * here too before they could ever be serialized out.
 */
public record UserSummary(Long id, String username, String email, String role) {

    /**
     * Builds the outward-facing view from an internal AppUser entity.
     * role().name() converts the Role enum (USER / ADMIN) to its plain
     * string form for JSON output.
     */
    public static UserSummary from(AppUser user) {
        return new UserSummary(
                user.getId(),
                user.getLoginName(),
                user.getEmailAddress(),
                user.getRole().name());
    }
}
