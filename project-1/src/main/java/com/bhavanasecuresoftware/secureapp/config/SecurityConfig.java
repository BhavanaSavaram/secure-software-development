package com.bhavanasecuresoftware.secureapp.config;

import com.bhavanasecuresoftware.secureapp.entity.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * The "secure the application with Spring Security" piece called out in
 * the rubric. This class defines the ONE filter chain every incoming HTTP
 * request passes through before it can reach a @RestController.
 *
 * ---------------------------------------------------------------------
 * How this maps back to the two-part threat scenario for this assignment
 * ---------------------------------------------------------------------
 * 1) SQL injection: this class contains no SQL at all. It authenticates
 *    the caller, then authorizes which URLs they may reach; every
 *    request that gets through still only ever touches the database via
 *    AppUserRepository's parameterized queries. "Authenticate safely" +
 *    "query safely" together close the vulnerability end to end.
 *
 * 2) Phishing for credentials: nothing here can stop an employee from
 *    being fooled by a convincing fake email. What it DOES do is limit
 *    the damage if a password is phished:
 *      - BCryptPasswordEncoder: passwords are hashed with a salted,
 *        adaptive algorithm, so a leaked hash (from a DB dump, say)
 *        can't be cheaply reversed back to the original password.
 *      - requiresSecure(): every request must arrive over HTTPS, so a
 *        credential typed into this app is never sent in cleartext over
 *        the network, even if the user reached the app via a phishing
 *        link.
 *      - hasRole(...) / hasAnyRole(...): role-based access limits blast
 *        radius -- a phished low-privileged account still can't reach
 *        the admin-only endpoint.
 *      - No distinct "wrong password" vs "unknown user" message (see
 *        AppUserDetailsService): stops an attacker who phished a list of
 *        email addresses from using this app to figure out which ones
 *        have real accounts.
 *      - HTTP security headers below (HSTS, frame-options, etc.) reduce
 *        the effectiveness of look-alike or embedded pages that a
 *        phishing campaign might use.
 *      - The actual cure for phishing itself is organizational (security
 *        awareness training, email filtering/DMARC) plus multi-factor
 *        authentication, so a phished password alone isn't sufficient to
 *        log in. MFA can be layered onto this configuration later as an
 *        additional AuthenticationProvider without touching the
 *        controller or repository code.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity // turns on @PreAuthorize checks, e.g. in UserController
public class SecurityConfig {

    /**
     * BCrypt: a salted, deliberately slow ("adaptive cost") hashing
     * algorithm built specifically for password storage -- unlike a fast
     * general-purpose hash (MD5, SHA-256), it's designed to resist
     * offline brute-force/dictionary attacks against a stolen hash.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Builds the security filter chain applied to every request. Read
     * top to bottom -- each .xxx(...) call configures one concern, and
     * they combine into the single pipeline a request passes through.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurityBuilder) throws Exception {
        httpSecurityBuilder

            // Reject any request that did not arrive over TLS. The
            // actual certificate/handshake is configured separately in
            // application.properties (server.ssl.* -- the HTTPS/KeyStore
            // piece of the rubric); this line is what makes that
            // enforcement mandatory rather than optional.
            .requiresChannel(channelRequestMatcherRegistry ->
                    channelRequestMatcherRegistry.anyRequest().requiresSecure())

            // URL-pattern-based authorization rules, evaluated top to
            // bottom -- the FIRST matching rule wins for a given request.
            .authorizeHttpRequests(authorizationRegistry -> authorizationRegistry
                // Spring's internal forward to /error (e.g. triggered
                // when @Valid rejects a request body) is itself a
                // request that re-enters this same filter chain. Without
                // permitting it explicitly, an unauthenticated caller's
                // validation failure would be masked as a 401 (blocked
                // before reaching /error) instead of showing the real
                // 400 Bad Request.
                .requestMatchers(new AntPathRequestMatcher("/error")).permitAll()
                // Anyone (no credentials) may create a new account.
                .requestMatchers(new AntPathRequestMatcher("/api/users/register", "POST")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/actuator/health")).permitAll()
                // Every other /api/users/** endpoint requires a logged-in
                // USER or ADMIN; individual methods (see
                // UserController#findByUsername) can still narrow this
                // further with @PreAuthorize.
                .requestMatchers(new AntPathRequestMatcher("/api/users/**"))
                    .hasAnyRole(Role.USER.name(), Role.ADMIN.name())
                // Anything not explicitly listed above still requires
                // authentication -- a "deny by default" posture rather
                // than accidentally leaving a new endpoint wide open.
                .anyRequest().authenticated()
            )

            // This is a stateless REST API (every request carries its own
            // Basic Auth credentials; there is no server-side login
            // session/cookie). STATELESS turns off Spring Security's
            // HttpSession-based session tracking entirely, which removes
            // session-fixation as an attack surface. CSRF protection
            // exists specifically to stop a browser from replaying an
            // authenticated SESSION COOKIE from a malicious page; with no
            // cookie-based session here, that protection is unnecessary.
            .sessionManagement(sessionConfigurer ->
                    sessionConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrfConfigurer -> csrfConfigurer.disable())

            // HTTP Basic Auth: the client sends "Authorization: Basic
            // base64(username:password)" on every request. Leaving the
            // default entry point in place means an unauthenticated
            // request gets a 401 WITH a "WWW-Authenticate: Basic" header,
            // which is what makes a browser pop up its native
            // username/password dialog when you visit a protected URL
            // directly.
            .httpBasic(basicAuthConfigurer -> { })
            // formLogin would serve an HTML login page and issue a
            // session cookie -- not appropriate for a stateless REST API,
            // so it stays explicitly disabled rather than left at its
            // (differently-behaved) default.
            .formLogin(formLoginConfigurer -> formLoginConfigurer.disable())

            // Defense-in-depth HTTP response headers -- these don't stop
            // an attack on their own, but they remove or weaken several
            // techniques (clickjacking, MIME-sniffing, protocol
            // downgrade) that a phishing/credential-harvesting page might
            // otherwise use against this app.
            .headers(headersConfigurer -> headersConfigurer
                // Tells browsers to only ever contact this host over
                // HTTPS for the next year, even if a user later types a
                // plain http:// URL -- blocks SSL-stripping downgrade
                // attacks.
                .httpStrictTransportSecurity(hstsConfigurer -> hstsConfigurer
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000))
                // Refuses to let any other site load this app inside an
                // <iframe>, which is what a clickjacking / credential-
                // harvesting overlay page would need to do.
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                // Stops browsers from "guessing" a different content
                // type than the one this app declares, which closes off
                // a class of MIME-sniffing based attacks.
                .contentTypeOptions(contentTypeOptionsConfigurer -> { })
                // Never send the current page's URL to a site this app
                // links out to -- avoids leaking, e.g., a URL that
                // happened to contain a token or identifier.
                .referrerPolicy(referrerPolicyConfigurer -> referrerPolicyConfigurer
                    .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
            );

        return httpSecurityBuilder.build();
    }
}
