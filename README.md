# Spring Security Implementation

A comprehensive Spring Boot project demonstrating robust authentication and authorization using Spring Security. This repository serves as a practical implementation of securing REST APIs, managing user roles, and handling secure logins.

## 🛡️ Key Features

*   **Authentication & Authorization:** Secure user login and endpoint protection.
*   **Role-Based Access Control (RBAC):** Differentiated access for `USER` and `ADMIN` roles.
*   **JWT Integration (Optional/If Applicable):** Stateless session management using JSON Web Tokens.
*   **Password Encryption:** Secure password hashing using `BCryptPasswordEncoder`.
*   **Custom UserDetailsService:** Database-backed user authentication loading user-specific data.
*   **Exception Handling:** Custom handling for `AccessDeniedException` and `AuthenticationException` (401 Unauthorized / 403 Forbidden).

## 🛠️ Tech Stack

*   **Java:** 17+ 
*   **Framework:** Spring Boot 3.x
*   **Security:** Spring Security
*   **Database ORM:** Spring Data JPA / Hibernate
*   **Database:** H2 (In-memory) / MySQL / PostgreSQL 
*   **Build Tool:** Maven / Gradle

## 📂 Architecture Overview

```text
src/main/java/com/suchfarm70/security
 ├── config        # SecurityFilterChain, PasswordEncoder, and CORS configurations
 ├── controller    # Secured and Public REST API endpoints
 ├── filter        # Custom security filters (e.g., JwtAuthFilter)
 ├── model         # User and Role JPA Entities
 ├── repository    # UserRepository for fetching credentials
 └── service       # CustomUserDetailsService and Auth business logic
