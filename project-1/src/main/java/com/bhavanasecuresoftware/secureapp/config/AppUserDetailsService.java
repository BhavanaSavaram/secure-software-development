package com.bhavanasecuresoftware.secureapp.config;

import com.bhavanasecuresoftware.secureapp.entity.AppUser;
import com.bhavanasecuresoftware.secureapp.repository.AppUserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * The bridge between Spring Security's authentication mechanism and this
 * application's own AppUser table. Spring Security calls
 * loadUserByUsername(...) automatically on every HTTP Basic Auth attempt
 * (see SecurityConfig's .httpBasic(...)); this class does not get invoked
 * directly by any of our own code.
 *
 * Security note: the lookup below reuses AppUserRepository's
 * findByLoginName(...), which -- like every other repository method -- is
 * a parameterized query. Submitting a classic injection payload as the
 * HTTP Basic username (e.g. admin' OR '1'='1' --) is looked up as a
 * literal, nonexistent username and simply fails authentication; it
 * cannot alter the query's logic.
 */
@Service
public class AppUserDetailsService implements UserDetailsService {

    private final AppUserRepository userRepository;

    public AppUserDetailsService(AppUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String attemptedUsername) throws UsernameNotFoundException {
        AppUser matchingUser = userRepository.findByLoginName(attemptedUsername)
                // Intentionally generic message: Spring Security converts
                // BOTH "no such user" and "password didn't match" into
                // the same 401 response further up the chain, so an
                // attacker working from a phished list of email
                // addresses/usernames can't tell which ones are real
                // accounts by comparing responses.
                .orElseThrow(() -> new UsernameNotFoundException("Invalid username or password"));

        // Spring Security compares the caller's submitted password
        // against getPassword() below using the same PasswordEncoder
        // configured in SecurityConfig (BCrypt) -- this class never
        // compares passwords itself.
        return User.builder()
                .username(matchingUser.getLoginName())
                .password(matchingUser.getHashedPassword())
                .authorities(List.of(new SimpleGrantedAuthority(matchingUser.getRole().toSpringAuthority())))
                .build();
    }
}
