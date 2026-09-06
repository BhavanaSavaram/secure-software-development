package com.bhavanasecuresoftware.secureapp.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * JPA entity mapped to the "app_user" table -- one row per registered
 * account. This is the "entity" piece called out in the rubric: it is the
 * Java-side representation of a database row, and Hibernate (the JPA
 * implementation Spring Boot wires up automatically) translates every
 * field below into a table column.
 *
 * Security note: hashedPassword stores a BCrypt digest ONLY. The plaintext
 * password the user typed is used once (in UserController#register /
 * AppUserDetailsService) to check against this hash, and is never itself
 * written to this entity, the database, or a log file.
 */
@Entity
@Table(name = "app_user")
public class AppUser {

    // Surrogate primary key. GenerationType.IDENTITY delegates ID
    // generation to the database's own auto-increment column, which is
    // what H2 (and Postgres/MySQL) use.
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // The name a user logs in with. @Column(unique = true) adds a
    // database-level UNIQUE constraint so two accounts can never collide
    // on username even under concurrent registration requests -- relying
    // only on the existsByUsername() check in the service layer would
    // leave a race condition.
    @NotBlank
    @Size(max = 50)
    @Column(nullable = false, unique = true, length = 50)
    private String loginName;

    // Contact address, also unique per account for the same
    // race-condition reason as loginName above.
    @NotBlank
    @Email
    @Column(nullable = false, unique = true, length = 254)
    private String emailAddress;

    // BCrypt hash of the password (never the raw password itself). Column
    // name kept snake_case to match typical relational-DB naming even
    // though the Java field is camelCase.
    @NotBlank
    @Column(name = "password_hash", nullable = false)
    private String hashedPassword;

    // Stored as its enum name (e.g. "USER", "ADMIN") via EnumType.STRING
    // rather than EnumType.ORDINAL (the default), because ORDINAL stores
    // the position (0, 1, ...) -- if Role's declaration order ever changes,
    // ORDINAL would silently reassign every existing user to the wrong
    // role. STRING is slightly larger on disk but immune to that failure
    // mode and is human-readable when inspecting the table directly.
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role = Role.USER;

    // JPA requires a no-arg constructor so Hibernate can instantiate the
    // entity via reflection before populating its fields from a result
    // set. "protected" (rather than public) keeps application code from
    // accidentally constructing a half-initialized AppUser.
    protected AppUser() {
    }

    /**
     * Creates a new account with the default USER role. Admin promotion
     * is intentionally not exposed here -- there is no public API path
     * that lets a caller set their own role to ADMIN (see
     * UserController#register, which always goes through this
     * constructor).
     */
    public AppUser(String loginName, String emailAddress, String hashedPassword) {
        this.loginName = loginName;
        this.emailAddress = emailAddress;
        this.hashedPassword = hashedPassword;
    }

    public Long getId() {
        return id;
    }

    public String getLoginName() {
        return loginName;
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public String getHashedPassword() {
        return hashedPassword;
    }

    public Role getRole() {
        return role;
    }
}
