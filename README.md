# 🔐 Spring Boot 3 & Spring Security 6/7 JWT Authentication Reference Implementation

[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Spring Security](https://img.shields.io/badge/Spring%20Security-6.x%2F7.x-blue.svg)](https://spring.io/projects/spring-security)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A robust, enterprise-ready reference implementation of stateless **JSON Web Token (JWT)** authentication and role-based authorization (RBAC) built using **Spring Boot 3+** and **Spring Security 6+/7+**.

---

## 📌 Features

- **Stateless Authentication:** Completely session-less security architecture using signed JWTs.
- **Dual-Token Architecture:** Access Tokens (short-lived) and Refresh Tokens (long-lived) mechanism.
- **Role-Based Access Control (RBAC):** Granular permissions using `@PreAuthorize` annotations and request matcher rules (`USER`, `ADMIN`, etc.).
- **Modern Security Configuration:** Pure Lambda DSL setup utilizing `SecurityFilterChain` without deprecated classes.
- **Password Security:** Salted BCrypt hashing via `PasswordEncoder`.
- **Custom Security Filter:** Custom `JwtAuthenticationFilter` extending `OncePerRequestFilter`.
- **Centralized Exception Handling:** Standardized handlers for unauthenticated (`401 Unauthorized`) and forbidden (`403 Forbidden`) attempts via custom `AuthenticationEntryPoint` and `AccessDeniedHandler`.
- **Database Integration:** JPA/Hibernate implementation supporting PostgreSQL/MySQL/H2.

---

## 🏗️ Architecture & Authentication Flow

```
+--------+            +-----------------------+            +---------------------+
| Client |            | AuthController        |            | JwtAuthentication   |
+---+----+            +-----------+-----------+            | Filter              |
    |                             |                        +----------+----------+
    |  1. POST /auth/login        |                                   |
    +---------------------------->|                                   |
    |  (Username & Password)      | 2. Authenticate Credentials       |
    |                             |-------------------------------->  |
    |                             | 3. Generate Access + Refresh Token|
    |  4. Return Tokens in cookies|<--------------------------------  |
    |<----------------------------|                                   |
    |                                                                 |
    |  5. Request with cookie containing access token				  |
    +---------------------------------------------------------------->|
    |                                                                 | 6. Validate Token
    |                                                                 | 7. Set SecurityContext
    |                                                                 |    Authentication
    |  8. Access Granted / Requested Data                             |
    |<----------------------------------------------------------------|
```

---

## 🛠️ Tech Stack

- **Language:** Java 17 / Java 21
- **Framework:** Spring Boot 3.x
- **Security:** Spring Security 6.x / 7.x
- **JWT Library:** `io.jsonwebtoken` (jjwt-api, jjwt-impl, jjwt-jackson)
- **Database:** PostgreSQL / H2 (In-memory for testing)
- **Persistence:** Spring Data JPA / Hibernate
- **Utilities:** Lombok, Jackson JSON parser

---

## ⚙️ Configuration Parameters

Configure your JWT secrets and token expiration periods inside `src/main/resources/application.yml`:

```yaml
jwt:
  properties:
    enabled: true
    secret: "9xA4vK2mZ8bQ5wP1rT7yC3eX6nM0vK2mZ8bQ5wP1rT7yC3eX6nM0" # Use a secure 256-bit key
    issuer: "issuer"
    accessTokenExpirationMillis: 900000   # 15 mins
    refreshTokenExpirationMillis: 604800000 # 7 days
    secureCookies: false
    publicEndpoints:
      - "/v3/api-docs/**"
      - "/api/v1/auth/**"
      - "/actuator/**"
    roleMappings:
      - pattern: "/api/v1/admin/**"
        roles: ["ADMIN"]
      - pattern: "/api/v1/learning/**"
        roles: ["LEARNER", "ADMIN"]
```

> ⚠️ **Security Tip:** Never hardcode secrets in source control for production. Use environment variables like `APPLICATION_SECURITY_JWT_SECRET_KEY=${JWT_SECRET}`.

---

## 🚀 Getting Started
### Prerequisites
- JDK 21 installed
- Gradle 8.x 
- PostgreSQL (Optional; H2 database profile available by default for local dev)

### Local Setup Steps
1. Clone the repository:
```
git clone [https://github.com/rkumar0206/jwt-security.git](https://github.com/rkumar0206/jwt-security.git)
cd jwt-security
```

2. pulish to mavenLocal()

```
./gradlew clean publishToMavenLocal --no-build-cache --no-configuration-cache
```

3. Include it in your build.gradle file

```
repositories {
	mavenCentral()
	mavenLocal()
}

dependencies {
	implementation 'com.rksdev:jwt-security:1.0.5'

}
```

---

## 🔌 API Endpoints Reference

### 1. Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/register` | Register a new user | ❌ Public |
| `POST` | `/api/v1/auth/login` | Authenticate user & get access/refresh token | ❌ Public |
| `POST` | `/api/v1/auth/refresh-token` | Obtain a new access token via refresh token | ❌ Public |

#### Sample Request: User Registration
`POST /api/v1/auth/register`
```json
{
  "username": "rohit.kumar",
  "email": "test@gmail.com",
  "password": "SecretPassword"
}
```

#### Sample Response: Authentication Success

<img width="513" height="225" alt="image" src="https://github.com/user-attachments/assets/494f7638-1bc7-46b3-8b08-b1918bcb9757" />

---

---

## 🔒 Security Best Practices Implemented

1. **Stateless Session Management:** Configured via `SessionCreationPolicy.STATELESS` preventing HTTP Session fixation attacks.
2. **Forbidden Anonymous Access:** All unmapped paths default to `authenticated()` rejection.
3. **CORS & CSRF Protection:** CSRF disabled specifically for stateless REST architectures, paired with configurable origin-based CORS filters.
4. **Custom Claims:** Ability to inject specific claims (such as user roles and metadata) into token payloads.
5. **Robust Token Validation:** Expiration dates, token structures, and digital signatures are verified on every incoming API request inside `JwtAuthenticationFilter`.

---



