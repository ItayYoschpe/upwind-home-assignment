# Threat Model

This document describes the threats considered before implementing the backend for PenguWave. It covers what could go wrong, what an attacker might try, and what I plan to protect against.

## System Overview

PenguWave is an internal web application used by security analysts to view and manage security events. The system handles sensitive security event data and user account management with role-based access.

## Threats and Mitigations

### 1. Credential Attacks

**Risk:** An attacker could brute-force login credentials, use credential stuffing from leaked databases, or exploit weak default passwords.

**Mitigation:** Passwords are hashed with bcrypt before storage - even if the database is compromised, plaintext passwords are not exposed. The API returns generic error messages on login failure ("Invalid email or password") to avoid revealing whether an email exists. In a production deployment, rate limiting should be added to the login endpoint to prevent brute-force attacks.

### 2. Broken Authentication

**Risk:** Stolen or leaked JWT tokens could allow unauthorized access. Tokens stored in localStorage are accessible to any JavaScript running on the page. Tokens without expiry would remain valid indefinitely.

**Mitigation:** JWTs are signed with a server-side secret and include an expiration time. The frontend clears the token on logout. The `/api/auth/me` endpoint validates the token on every load so stale sessions are detected.

### 3. Broken Authorization (IDOR / Privilege Escalation)

**Risk:** A non-admin user could attempt to access the user management API, view events belonging to other users, or modify their own role to gain admin privileges.

**Mitigation:** Authorization is enforced server-side with middleware. User management endpoints require the `admin` role. The `PATCH /api/users/:id` endpoint validates role and status values and prevents privilege escalation. Events are filtered by `userId` for non-admin users - they can only see their own events. Disabled accounts are prevented from logging in. All authorization checks happen on the backend, the frontend hides UI elements but the backend is the enforcement boundary.

### 4. Cross-Site Scripting (XSS)

**Risk:** The existing frontend has two XSS vulnerabilities: `dangerouslySetInnerHTML` rendering raw user search input, and `innerHTML` rendering event descriptions. An attacker could craft a malicious event description or trick a user into searching for a payload that executes arbitrary JavaScript.

**Mitigation:** Both XSS sinks are replaced with safe text rendering. Search results use React's built-in text escaping. Event descriptions are rendered as plain text instead of HTML.

### 5. Data Exposure

**Risk:** The existing frontend displays passwords in plain text on the user management page. API responses could accidentally include password hashes. Verbose error messages could leak internal details.

**Mitigation:** The password column is removed from the frontend. The backend never includes password hashes in any API response. Error responses use a consistent `{ "error": "..." }` format with human-readable but non-leaking messages.

### 6. Injection (SQL Injection)

**Risk:** If user input is concatenated into SQL queries, an attacker could manipulate queries to read, modify, or delete data.

**Mitigation:** All database queries use parameterized statements. No string concatenation is used in query construction.
