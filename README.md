# Application Security Portal

A clean, full-stack cybersecurity demonstration portal built for academic evaluation. This project showcases foundational secure coding principles, defense-in-depth architecture, stateless token-based authentication, role-based authorization (RBAC), cryptographic password hashing, rate limiting, and HTTP header hardening without relying on third-party database engines or heavy frontend frameworks.

---

## 📋 Table of Contents
1. [Project Overview](#-project-overview)
2. [Key Security Concepts Demonstrated](#-key-security-concepts-demonstrated)
3. [Technology Stack](#-technology-stack)
4. [Project Structure](#-project-structure)
5. [Demo User Credentials](#-demo-user-credentials)
6. [Installation & Setup](#-installation--setup)
7. [Running the Application](#-running-the-application)
8. [API Endpoints Reference](#-api-endpoints-reference)
9. [Evaluation & Testing Walkthrough](#-evaluation--testing-walkthrough)

---

## 🎯 Project Overview

The **Application Security Portal** is designed to demonstrate how defensive security controls are implemented across both the frontend and backend in modern web applications. 

### Core Objectives:
- **Zero Plaintext Passwords:** Strict one-way cryptographic hashing using Bcrypt.
- **Stateless Authentication:** JSON Web Token (JWT) transmission via `Authorization: Bearer` headers.
- **Fine-Grained Authorization:** Role-Based Access Control (RBAC) preventing unauthorized access to administrative endpoints (HTTP 403 Forbidden).
- **Comprehensive Input Validation:** Dual-layer validation (client & server) preventing invalid or malformed data submissions.
- **Brute-Force Defense:** Rate limiting on authentication routes to mitigate automated credential attacks.
- **Secure Error Responses:** Standardized, sanitized error responses that prevent internal stack trace and architecture leakage.

---

## 🛡️ Key Security Concepts Demonstrated

| Security Concept | Implementation Mechanism | Purpose |
| :--- | :--- | :--- |
| **Input Validation** | Client regex & Server validation middleware | Ensures valid email formats, min 8-char passwords, matching confirmation, and prevents injection. |
| **Password Hashing** | `bcryptjs` (10 Salt Rounds) | Protects credentials against rainbow table and database exposure attacks. |
| **Authentication** | `jsonwebtoken` (JWT HMAC-SHA256) | Issues signed, tamper-proof bearer tokens with expiration for stateless user verification. |
| **Authorization (RBAC)** | `requireAdmin` Express Middleware | Distinguishes between `user` and `admin` roles, returning `403 Forbidden` for unauthorized attempts. |
| **Rate Limiting** | `express-rate-limit` | Caps login attempts to 10 per 15 minutes per IP to block brute-force attacks. |
| **HTTP Hardening** | `helmet` | Injects protective headers (`X-Content-Type-Options`, `CSP`, `HSTS`, `X-Frame-Options`). |
| **Error Handling** | Standardized JSON `{ success, message }` | Conceals stack traces and database schemas from external attackers. |

---

## 💻 Technology Stack

### Frontend
- **HTML5:** Semantic, accessible layout.
- **CSS3:** Custom responsive styling with clear security status indicators.
- **Vanilla JavaScript:** Native `fetch()` API for asynchronous communication and token management.

### Backend
- **Node.js & Express.js:** Fast, lightweight RESTful API server.
- **bcryptjs:** Cryptographic password hashing.
- **jsonwebtoken (JWT):** Secure token generation and verification.
- **helmet:** HTTP header hardening.
- **express-rate-limit:** Brute-force and DoS mitigation.
- **cors:** Cross-Origin Resource Sharing control.
- **dotenv:** Environment configuration.

---

## 📁 Project Structure

```
Application Security/
│
├── frontend/
│   ├── index.html       # Single-page interface (Auth forms, Dashboard, RBAC test, Security cards)
│   ├── style.css        # Clean, classic stylesheet with security badges & responsive layout
│   └── script.js        # Fetch API calls, JWT session handling, client validation & dynamic views
│
├── backend/
│   ├── server.js        # Express REST API, security middleware, JWT/Bcrypt logic, in-memory store
│   ├── package.json     # Node.js project manifest and dependencies
│   └── .env             # Environment variables (PORT, JWT_SECRET, JWT_EXPIRES_IN)
│
└── README.md            # Comprehensive project documentation and evaluation guide
```

---

## 🔑 Demo User Credentials

The backend automatically initializes two memory-resident demonstration accounts with pre-hashed Bcrypt passwords:

| Role | Email Address | Password | Privileges |
| :--- | :--- | :--- | :--- |
| **👑 Admin** | `admin@example.com` | `Admin@123` | Full access to user telemetry and `GET /api/admin` |
| **👤 User** | `user@example.com` | `User@123` | Standard dashboard access; restricted from admin endpoints |

*(Tip: The frontend login interface contains quick-fill buttons for both demo accounts for 1-click evaluation!)*

---

## ⚙️ Installation & Setup

### Prerequisites
- **Node.js** (v14 or newer) and **npm** installed on your system.

### Step 1: Install Backend Dependencies
Open a terminal in the project directory and run:

```bash
cd backend
npm install
```

---

## 🚀 Running the Application

### 1. Start the Backend Server
From inside the `backend/` directory, run:

```bash
npm start
```
*The Express server will start on `http://localhost:5000`.*

```
=================================================
 Application Security Server running on port 5000
 Backend URL: http://localhost:5000
 Demo Accounts:
   - Admin: admin@example.com / Admin@123 (role: admin)
   - User:  user@example.com  / User@123  (role: user)
=================================================
```

### 2. Launch the Frontend
Open `frontend/index.html` in any modern web browser:
- **Direct file opening:** Double click `frontend/index.html` in File Explorer.
- **VS Code Live Server:** Right-click `frontend/index.html` -> *Open with Live Server*.
- **Python local server (optional):**
  ```bash
  cd frontend
  python -m http.server 3000
  ```
  Then visit `http://localhost:3000` in your browser.

---

## 📡 API Endpoints Reference

| Method | Endpoint | Auth Required | Role Required | Description |
| :--- | :--- | :---: | :---: | :--- |
| `POST` | `/api/register` | No | Any | Validates input, hashes password with bcrypt, creates account. |
| `POST` | `/api/login` | No | Any | Validates credentials, checks bcrypt hash, returns signed JWT. |
| `GET` | `/api/dashboard` | **Yes (JWT)** | Any | Returns authenticated user info and security status checks. |
| `GET` | `/api/admin` | **Yes (JWT)** | `admin` | Returns system security metrics and registered users (403 for regular users). |
| `GET` | `/api/security` | No | Any | Returns security best practices and architectural recommendations. |

---

## 🧪 Evaluation & Testing Walkthrough

Follow these steps to demonstrate and verify all security features:

### Test 1: User Registration & Validation (400 Bad Request)
1. Navigate to the **Register** tab.
2. Attempt to register with a password shorter than 8 characters (e.g. `12345`) or mismatched confirm password.
3. Observe client-side and server-side validation error messages preventing registration.
4. Enter valid details (e.g., Name: `Charlie`, Email: `charlie@example.com`, Password: `Password@123`).
5. Submit and receive HTTP `201 Created` with a confirmation alert.

### Test 2: Authentication & Password Verification (401 Unauthorized)
1. Navigate to the **Login** tab.
2. Enter an incorrect password for `user@example.com` (e.g., `WrongPassword`).
3. Observe the generic `401 Unauthorized` message (`Invalid email or password`) preventing username enumeration.
4. Enter the correct password `User@123`.
5. Observe successful login, JWT issuance, and redirection to the Dashboard.

### Test 3: Role-Based Authorization Enforcement (403 Forbidden)
1. While logged in as `user@example.com` (Role: `user`), observe the **Admin Restricted Zone** panel.
2. Click **⚡ Test Access to GET /api/admin**.
3. Observe the live backend response: **`HTTP 403 Forbidden`** with `{ "success": false, "message": "Access forbidden: Administrator privileges are required to access this resource." }`.
4. Log out and sign in using the **👑 Admin Demo** (`admin@example.com` / `Admin@123`).
5. Notice that the Admin Dashboard opens with **`HTTP 200 OK`**, displaying registered users and server security telemetry.

### Test 4: Brute-Force Rate Limiting (429 Too Many Requests)
1. Attempt 10 rapid incorrect logins on `/api/login`.
2. The server triggers the `express-rate-limit` rule and returns **`HTTP 429 Too Many Requests`**.

---

## 📜 License
This project is built for educational and demonstration purposes.
