# Secure Access to Database over HTTPS — Spring Boot

Addresses two threats from the assignment scenario:
1. A **SQL injection**–vulnerable web application.
2. A **phishing email** impersonating IT and requesting login credentials.

The design does not "detect phishing" (no app can) — it limits what a
phished credential, or an injection attempt, can actually do.

## 1. Spring Boot application setup
- [`pom.xml`](pom.xml) — Spring Boot 3.3.4 / Java 17, with `spring-boot-starter-web`,
  `-data-jpa`, `-security`, `-validation`, and the H2 in-memory driver for local dev.
- [`SecureAppApplication.java`](src/main/java/com/bhavanasecuresoftware/secureapp/SecureAppApplication.java) — entry point.
- [`application.properties`](src/main/resources/application.properties) — server, TLS, and datasource config.

## 2. KeyStore for HTTPS, entity, repository, controller
- [`scripts/generate-keystore.sh`](scripts/generate-keystore.sh) — creates a self-signed
  PKCS12 keystore (`src/main/resources/keystore.p12`, **git-ignored**) with `keytool`.
  `application.properties` points `server.ssl.key-store` at it and forces TLS 1.2/1.3
  on port 8443, so credentials and data are encrypted in transit — a network sniffer
  positioned between a phished user and the server can't harvest the password even if
  the user is misdirected to it.
- [`entity/AppUser.java`](src/main/java/com/bhavanasecuresoftware/secureapp/entity/AppUser.java) — JPA entity; stores a BCrypt hash, never a plaintext password.
- [`repository/AppUserRepository.java`](src/main/java/com/bhavanasecuresoftware/secureapp/repository/AppUserRepository.java) — Spring Data JPA repository. Every method here compiles to a **parameterized query / PreparedStatement**, which is the actual fix for SQL injection:
  ```java
  // VULNERABLE (never do this):
  String sql = "SELECT * FROM app_user WHERE username = '" + input + "'";
  // input = admin' OR '1'='1  -->  returns every row, or worse.

  // SAFE (what this repository does):
  @Query("SELECT u FROM AppUser u WHERE u.username = :username")
  Optional<AppUser> findByUsernameExplicit(@Param("username") String username);
  // input is always bound as data, never spliced into the query text.
  ```
- [`controller/UserController.java`](src/main/java/com/bhavanasecuresoftware/secureapp/controller/UserController.java) — REST endpoints (`/api/users/register`, `/me`, `/{username}`) that only ever reach the DB through the repository above; responses use a `UserSummary` DTO so a password hash can never leak in a response body.

## 3. Secure the application with Spring Security
- [`config/SecurityConfig.java`](src/main/java/com/bhavanasecuresoftware/secureapp/config/SecurityConfig.java):
  - Forces every request over HTTPS (`requiresChannel(...).requiresSecure()`).
  - `BCryptPasswordEncoder` for password storage — adaptive + salted, so a stolen
    hash from a DB dump (or a phished credential reused elsewhere) resists offline
    cracking and can't be reversed to the original password.
  - Role-based authorization (`hasAnyRole`, `@PreAuthorize`) — even if one account's
    credentials are phished, the attacker only gets that account's role, not
    unrestricted database access.
  - Generic 401 on both "unknown user" and "wrong password" (see
    [`AppUserDetailsService`](src/main/java/com/bhavanasecuresoftware/secureapp/config/AppUserDetailsService.java)) so an attacker working from a phished
    email list can't enumerate valid usernames from response differences.
  - Security headers: HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
    strict `Referrer-Policy` — reduce the effectiveness of look-alike/embedded pages
    used in phishing/clickjacking.
  - `RegisterRequest` ([`dto/RegisterRequest.java`](src/main/java/com/bhavanasecuresoftware/secureapp/dto/RegisterRequest.java)) applies Bean Validation
    (`@Pattern`, `@Size`, `@Email`) as a second line of defense in front of the
    parameterized repository layer.

**What this design does *not* claim to solve:** it cannot stop an employee from
being fooled by a convincing phishing email. That risk is reduced organizationally
(security-awareness training, email/DMARC filtering) and technically by adding
**multi-factor authentication** on top of this password check — the codebase is
structured so an MFA provider can be added without touching the controller or
repository layer.

## Running it

Requires JDK 17+ and Maven (verified in this environment with
`brew install openjdk@17 maven`, since the base machine only had Java 8).

```bash
export JAVA_HOME="/opt/homebrew/opt/openjdk@17"
export PATH="$JAVA_HOME/bin:$PATH"
./scripts/generate-keystore.sh   # one-time: creates src/main/resources/keystore.p12
mvn spring-boot:run
```

Then, e.g.:

```bash
curl -sk -X POST https://localhost:8443/api/users/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"CorrectHorseBattery1"}'

curl -sk -u alice:CorrectHorseBattery1 https://localhost:8443/api/users/me
```

`-k` is only needed because the generated cert is self-signed for local dev.

### Verified in this environment
- Compiles cleanly with `mvn compile`.
- App starts, serves TLS 1.3 on 8443 with the generated certificate.
- Registration, authentication, and role checks work end-to-end (201 / 401 / 200 / 403
  observed via `curl`).
- A classic SQL-injection-style username (`robert'); DROP TABLE app_user;--`) is
  **rejected by Bean Validation with 400**, never reaches the database, and a similar
  payload used as HTTP Basic credentials or as a path variable is safely rejected
  (401 / 403) with no stack trace or bypass — confirming the repository's
  parameterized queries and the security filter chain both hold up.
