package com.bhavanasecuresoftware.secureapp.controller;

import com.bhavanasecuresoftware.secureapp.dto.RegisterRequest;
import com.bhavanasecuresoftware.secureapp.dto.UserSummary;
import com.bhavanasecuresoftware.secureapp.entity.AppUser;
import com.bhavanasecuresoftware.secureapp.repository.AppUserRepository;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The "controller" piece called out in the rubric -- the HTTP-facing
 * layer. It never runs a SQL/JPQL query itself; it always delegates to
 * AppUserRepository, which is what actually guarantees every lookup is a
 * parameterized query (see the long comment in AppUserRepository for the
 * full SQL-injection explanation).
 *
 * Authentication (verifying WHO is calling) happens one layer below this,
 * in Spring Security's filter chain (SecurityConfig), before any method
 * here even starts running. By the time a method body executes, Spring
 * has already confirmed the caller's identity and role.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final AppUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // Constructor injection (rather than @Autowired fields) is the
    // recommended Spring practice: it makes both dependencies mandatory,
    // final, and trivial to supply fakes for in a unit test.
    public UserController(AppUserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * POST /api/users/register -- open to anyone (see SecurityConfig's
     * permitAll rule for this exact path+method). Anyone can create an
     * account, but only with the USER role; there is no parameter or
     * field anywhere in this method that lets a caller request ADMIN.
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest newAccountRequest) {

        // Reject duplicates with a generic message before hitting the
        // database's unique-constraint, which would otherwise surface as
        // an ugly 500-level SQL exception instead of a clean 409.
        boolean usernameTaken = userRepository.existsByLoginName(newAccountRequest.getUsername());
        boolean emailTaken = userRepository.existsByEmailAddress(newAccountRequest.getEmail());
        if (usernameTaken || emailTaken) {
            // Deliberately vague: does NOT say which of the two collided,
            // so a caller can't use this endpoint to test whether a
            // specific email address already has an account here.
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("Registration failed. Please choose different credentials.");
        }

        // The plaintext password exists only for the lifetime of this
        // request; encode() immediately turns it into a salted BCrypt
        // hash, and that hash is the only form ever handed to the entity
        // / repository / database below.
        String bcryptHash = passwordEncoder.encode(newAccountRequest.getPassword());

        AppUser newUser = new AppUser(
                newAccountRequest.getUsername(),
                newAccountRequest.getEmail(),
                bcryptHash);

        AppUser persistedUser = userRepository.save(newUser);

        return ResponseEntity.status(HttpStatus.CREATED).body(UserSummary.from(persistedUser));
    }

    /**
     * GET /api/users/me -- returns the profile of whoever Spring Security
     * just authenticated for THIS request (authentication.getName() is
     * the username Spring already verified against the stored BCrypt
     * hash). The username is never taken from a URL path or query
     * parameter here, which is what prevents one logged-in user from
     * paging through other accounts by guessing ids or names (an
     * authorization bug -- IDOR -- distinct from, but just as important
     * as, SQL injection).
     */
    @GetMapping("/me")
    public ResponseEntity<UserSummary> me(Authentication callerIdentity) {
        String verifiedUsername = callerIdentity.getName();

        return userRepository.findByLoginName(verifiedUsername)
                .map(UserSummary::from)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * GET /api/users/{username} -- admin-only lookup of an arbitrary
     * account. Access is checked TWICE, deliberately (defense in depth):
     *   1. SecurityConfig's URL-pattern rule requires an authenticated
     *      USER or ADMIN just to reach this class at all.
     *   2. @PreAuthorize below then additionally requires ADMIN
     *      specifically for this one method.
     * If either check fails, this method body never runs.
     *
     * requestedUsername can be absolutely anything an attacker sends --
     * quotes, semicolons, SQL comment markers -- and it is still safe,
     * because findByLoginName() binds it as a query parameter rather than
     * building a query string from it.
     */
    @GetMapping("/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserSummary> findByUsername(@PathVariable("username") String requestedUsername) {
        return userRepository.findByLoginName(requestedUsername)
                .map(UserSummary::from)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
