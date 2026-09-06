package com.bhavanasecuresoftware.secureapp.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * The JSON body a client sends to POST /api/users/register.
 *
 * This class is a DTO (Data Transfer Object): a plain holder for
 * inbound/outbound data that is separate from the AppUser JPA entity.
 * Keeping them separate is a best practice -- it means the entity's
 * database shape (ids, the hashed password column, etc.) is never
 * directly exposed to or populated from raw client JSON.
 *
 * Bean Validation (the @NotBlank / @Size / @Pattern / @Email annotations)
 * runs automatically when a controller method parameter is annotated
 * with @Valid (see UserController#register). A request that fails any of
 * these checks never reaches the controller body, and therefore never
 * reaches the database -- this is a second, independent layer of defense
 * in front of the parameterized queries in AppUserRepository.
 */
public class RegisterRequest {

    // NOTE ON NAMING: these three fields are deliberately kept as
    // "username" / "email" / "password" rather than more descriptive
    // internal-style names. They define the JSON contract the client
    // sends (e.g. {"username": "...", "email": "...", "password": "..."})
    // -- renaming them would just rename the JSON keys every caller has
    // to send, with no clarity benefit. Internal-only code (entity
    // fields, local variables, config) is where the more descriptive
    // renames in this codebase were applied instead.

    // Only letters, digits, and underscore are accepted. This is a
    // deliberately strict allow-list (rather than trying to block-list
    // dangerous characters like quotes or semicolons) -- allow-listing is
    // the more robust approach because it can't be bypassed by a
    // character the block-list author didn't think of.
    @NotBlank
    @Size(min = 3, max = 50)
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "username may only contain letters, digits, underscore")
    private String username;

    @NotBlank
    @Email
    @Size(max = 254)
    private String email;

    // A 12-character minimum makes the password space large enough to
    // resist offline brute-forcing of a stolen BCrypt hash, and reduces
    // the odds that a password phished for THIS system is a short,
    // easily-guessed string that also unlocks the user's other accounts.
    @NotBlank
    @Size(min = 12, max = 128)
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
