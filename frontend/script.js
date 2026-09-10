/**
 * Application Security Portal - Frontend Client Logic
 * Handles Authentication, Authorization (RBAC), Validation, and API Communication
 */

const API_BASE = 'http://localhost:5000/api';

// State keys for session persistence
const TOKEN_STORAGE_KEY = 'appsec_jwt_token';
const USER_STORAGE_KEY = 'appsec_user_data';

// ==========================================
// DOM ELEMENTS
// ==========================================

// Views
const authView = document.getElementById('auth-view');
const dashboardView = document.getElementById('dashboard-view');

// Nav Controls
const navUserControls = document.getElementById('nav-user-controls');
const navUserBadge = document.getElementById('nav-user-badge');
const navUserEmail = document.getElementById('nav-user-email');
const logoutBtn = document.getElementById('logout-btn');

// Alert Banner
const alertBox = document.getElementById('alert-box');
const alertIcon = document.getElementById('alert-icon');
const alertMessage = document.getElementById('alert-message');
const alertCloseBtn = document.getElementById('alert-close');

// Tabs & Forms
const tabLogin = document.getElementById('tab-login');
const tabRegister = document.getElementById('tab-register');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const switchToRegisterLink = document.getElementById('switch-to-register');
const switchToLoginLink = document.getElementById('switch-to-login');

// Quick Demo Fill Buttons
const fillAdminBtn = document.getElementById('fill-admin-btn');
const fillUserBtn = document.getElementById('fill-user-btn');

// Login Form Elements
const loginEmailInput = document.getElementById('login-email');
const loginPasswordInput = document.getElementById('login-password');
const loginEmailError = document.getElementById('login-email-error');
const loginPasswordError = document.getElementById('login-password-error');
const loginSubmitBtn = document.getElementById('login-submit-btn');

// Register Form Elements
const registerNameInput = document.getElementById('register-name');
const registerEmailInput = document.getElementById('register-email');
const registerPasswordInput = document.getElementById('register-password');
const registerConfirmPasswordInput = document.getElementById('register-confirm-password');
const registerNameError = document.getElementById('register-name-error');
const registerEmailError = document.getElementById('register-email-error');
const registerPasswordError = document.getElementById('register-password-error');
const registerConfirmError = document.getElementById('register-confirm-error');
const registerSubmitBtn = document.getElementById('register-submit-btn');

// Dashboard Elements
const dashboardWelcomeMsg = document.getElementById('dashboard-welcome-msg');
const userEmailDisplay = document.getElementById('user-email-display');
const userRoleBadge = document.getElementById('user-role-badge');
const statusAuthDesc = document.getElementById('status-auth-desc');
const statusHashDesc = document.getElementById('status-hash-desc');
const statusValidationDesc = document.getElementById('status-validation-desc');
const statusAuthzDesc = document.getElementById('status-authz-desc');
const statusAuthzPill = document.getElementById('status-authz-pill');

// Admin & Restricted Panels
const adminPanel = document.getElementById('admin-panel');
const adminUserCount = document.getElementById('admin-user-count');
const adminUsersTableBody = document.getElementById('admin-users-table-body');
const userRestrictedPanel = document.getElementById('user-restricted-panel');
const testAdminRouteBtn = document.getElementById('test-admin-route-btn');
const adminTestResult = document.getElementById('admin-test-result');
const testResultBadge = document.getElementById('test-result-badge');
const testResultBody = document.getElementById('test-result-body');

// Security Recommendations
const recommendationsContainer = document.getElementById('recommendations-container');

// ==========================================
// UTILITY & NOTIFICATION HELPERS
// ==========================================

function showAlert(message, type = 'danger') {
    alertBox.className = `alert-box alert-${type}`;
    
    if (type === 'success') {
        alertIcon.textContent = '✅';
    } else if (type === 'warning') {
        alertIcon.textContent = '⚠️';
    } else {
        alertIcon.textContent = '❌';
    }

    alertMessage.textContent = message;
    alertBox.classList.remove('hidden');

    // Auto dismiss success alerts after 5 seconds
    if (type === 'success') {
        setTimeout(() => {
            hideAlert();
        }, 5000);
    }
}

function hideAlert() {
    alertBox.classList.add('hidden');
}

alertCloseBtn.addEventListener('click', hideAlert);

function isValidEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
}

function clearFieldErrors() {
    loginEmailError.textContent = '';
    loginPasswordError.textContent = '';
    registerNameError.textContent = '';
    registerEmailError.textContent = '';
    registerPasswordError.textContent = '';
    registerConfirmError.textContent = '';

    const inputs = document.querySelectorAll('.form-control');
    inputs.forEach(input => {
        input.classList.remove('is-invalid', 'is-valid');
    });
}

// ==========================================
// TAB SWITCHING
// ==========================================

function showLoginTab() {
    tabLogin.classList.add('active');
    tabRegister.classList.remove('active');
    loginForm.classList.remove('hidden');
    registerForm.classList.add('hidden');
    clearFieldErrors();
    hideAlert();
}

function showRegisterTab() {
    tabRegister.classList.add('active');
    tabLogin.classList.remove('active');
    registerForm.classList.remove('hidden');
    loginForm.classList.add('hidden');
    clearFieldErrors();
    hideAlert();
}

tabLogin.addEventListener('click', showLoginTab);
tabRegister.addEventListener('click', showRegisterTab);
switchToRegisterLink.addEventListener('click', (e) => {
    e.preventDefault();
    showRegisterTab();
});
switchToLoginLink.addEventListener('click', (e) => {
    e.preventDefault();
    showLoginTab();
});

// ==========================================
// QUICK DEMO AUTO-FILL
// ==========================================

fillAdminBtn.addEventListener('click', () => {
    showLoginTab();
    loginEmailInput.value = 'admin@example.com';
    loginPasswordInput.value = 'Admin@123';
    clearFieldErrors();
    showAlert('Loaded Demo Admin credentials. Click "Sign In" to proceed.', 'warning');
});

fillUserBtn.addEventListener('click', () => {
    showLoginTab();
    loginEmailInput.value = 'user@example.com';
    loginPasswordInput.value = 'User@123';
    clearFieldErrors();
    showAlert('Loaded Demo User credentials. Click "Sign In" to proceed.', 'warning');
});

// ==========================================
// AUTHENTICATION LOGIC (LOGIN & REGISTER)
// ==========================================

// Handle Login
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearFieldErrors();
    hideAlert();

    const email = loginEmailInput.value.trim();
    const password = loginPasswordInput.value;
    let hasError = false;

    // Client-side Input Validation
    if (!email) {
        loginEmailError.textContent = 'Email address is required.';
        loginEmailInput.classList.add('is-invalid');
        hasError = true;
    } else if (!isValidEmail(email)) {
        loginEmailError.textContent = 'Please enter a valid email format.';
        loginEmailInput.classList.add('is-invalid');
        hasError = true;
    }

    if (!password) {
        loginPasswordError.textContent = 'Password is required.';
        loginPasswordInput.classList.add('is-invalid');
        hasError = true;
    }

    if (hasError) return;

    loginSubmitBtn.disabled = true;
    loginSubmitBtn.textContent = 'Authenticating...';

    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            // Save Token and User Data in Session Storage
            sessionStorage.setItem(TOKEN_STORAGE_KEY, data.token);
            sessionStorage.setItem(USER_STORAGE_KEY, JSON.stringify(data.user));

            loginForm.reset();
            showAlert('Authentication successful! Loading dashboard...', 'success');
            
            // Load dashboard
            await loadDashboard();
        } else {
            showAlert(data.message || 'Login failed. Please verify your credentials.', 'danger');
        }
    } catch (err) {
        console.error('Login error:', err);
        showAlert('Network error: Unable to connect to backend server at ' + API_BASE, 'danger');
    } finally {
        loginSubmitBtn.disabled = false;
        loginSubmitBtn.textContent = 'Sign In';
    }
});

// Handle Register
registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearFieldErrors();
    hideAlert();

    const name = registerNameInput.value.trim();
    const email = registerEmailInput.value.trim();
    const password = registerPasswordInput.value;
    const confirmPassword = registerConfirmPasswordInput.value;
    let hasError = false;

    // Client-side Input Validation
    if (!name) {
        registerNameError.textContent = 'Full name is required.';
        registerNameInput.classList.add('is-invalid');
        hasError = true;
    }

    if (!email) {
        registerEmailError.textContent = 'Email address is required.';
        registerEmailInput.classList.add('is-invalid');
        hasError = true;
    } else if (!isValidEmail(email)) {
        registerEmailError.textContent = 'Please enter a valid email address.';
        registerEmailInput.classList.add('is-invalid');
        hasError = true;
    }

    if (!password) {
        registerPasswordError.textContent = 'Password is required.';
        registerPasswordInput.classList.add('is-invalid');
        hasError = true;
    } else if (password.length < 8) {
        registerPasswordError.textContent = 'Password must be at least 8 characters long.';
        registerPasswordInput.classList.add('is-invalid');
        hasError = true;
    }

    if (!confirmPassword) {
        registerConfirmError.textContent = 'Please confirm your password.';
        registerConfirmPasswordInput.classList.add('is-invalid');
        hasError = true;
    } else if (password !== confirmPassword) {
        registerConfirmError.textContent = 'Passwords do not match.';
        registerConfirmPasswordInput.classList.add('is-invalid');
        hasError = true;
    }

    if (hasError) return;

    registerSubmitBtn.disabled = true;
    registerSubmitBtn.textContent = 'Creating Account...';

    try {
        const response = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name, email, password, confirmPassword })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            registerForm.reset();
            showLoginTab();
            showAlert(data.message + ' You can now sign in with your credentials.', 'success');
            loginEmailInput.value = email;
            loginPasswordInput.focus();
        } else {
            showAlert(data.message || 'Registration failed.', 'danger');
        }
    } catch (err) {
        console.error('Registration error:', err);
        showAlert('Network error: Unable to connect to backend server at ' + API_BASE, 'danger');
    } finally {
        registerSubmitBtn.disabled = false;
        registerSubmitBtn.textContent = 'Complete Registration';
    }
});

// ==========================================
// DASHBOARD & DATA FETCHING
// ==========================================

async function loadDashboard() {
    const token = sessionStorage.getItem(TOKEN_STORAGE_KEY);

    if (!token) {
        showAuthView();
        return;
    }

    try {
        // Fetch Dashboard Info (Protected API)
        const response = await fetch(`${API_BASE}/dashboard`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (response.status === 401) {
            // Token expired or invalid
            handleLogout('Session expired or invalid. Please log in again.');
            return;
        }

        const result = await response.json();

        if (response.ok && result.success) {
            const { welcome, user, securityStatus } = result.data;

            // Render Dashboard User Info
            dashboardWelcomeMsg.textContent = welcome;
            userEmailDisplay.textContent = user.email;
            userRoleBadge.textContent = user.role.toUpperCase();
            userRoleBadge.className = `role-badge ${user.role}`;

            // Render Nav Controls
            navUserEmail.textContent = user.email;
            navUserBadge.textContent = user.role.toUpperCase();
            navUserBadge.className = `role-badge ${user.role}`;
            navUserControls.classList.remove('hidden');

            // Render Status Cards
            statusAuthDesc.textContent = securityStatus.authentication;
            statusHashDesc.textContent = securityStatus.passwordHashing;
            statusValidationDesc.textContent = securityStatus.inputValidation;
            statusAuthzDesc.textContent = securityStatus.authorization;

            if (user.role === 'admin') {
                statusAuthzPill.textContent = 'Full Admin Rights';
                statusAuthzPill.className = 'status-pill pill-admin';
            } else {
                statusAuthzPill.textContent = 'Protected User Rights';
                statusAuthzPill.className = 'status-pill pill-info';
            }

            // Render RBAC Section based on Role
            if (user.role === 'admin') {
                await loadAdminPanel(token);
                adminPanel.classList.remove('hidden');
                userRestrictedPanel.classList.add('hidden');
            } else {
                adminPanel.classList.add('hidden');
                userRestrictedPanel.classList.remove('hidden');
                adminTestResult.classList.add('hidden');
            }

            // Fetch and render Security Recommendations
            await loadSecurityRecommendations();

            // Toggle Views
            authView.classList.add('hidden');
            dashboardView.classList.remove('hidden');
        } else {
            handleLogout(result.message || 'Failed to authenticate session.');
        }
    } catch (err) {
        console.error('Dashboard load error:', err);
        showAlert('Failed to connect to backend server. Make sure the Node.js server is running on port 5000.', 'danger');
    }
}

// Load Admin Panel Data (Admins Only)
async function loadAdminPanel(token) {
    try {
        const response = await fetch(`${API_BASE}/admin`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const result = await response.json();

        if (response.ok && result.success) {
            const { totalUsersCount, registeredUsers } = result.securityInfo;

            adminUserCount.textContent = totalUsersCount;

            // Render User Table
            adminUsersTableBody.innerHTML = '';
            registeredUsers.forEach(u => {
                const row = document.createElement('tr');
                const dateStr = u.createdAt ? new Date(u.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'N/A';
                
                row.innerHTML = `
                    <td><strong>#${u.id}</strong></td>
                    <td>${escapeHtml(u.name)}</td>
                    <td>${escapeHtml(u.email)}</td>
                    <td><span class="role-badge ${u.role}">${u.role}</span></td>
                    <td style="color: #64748b; font-size: 0.8rem;">${dateStr}</td>
                `;
                adminUsersTableBody.appendChild(row);
            });
        }
    } catch (err) {
        console.error('Admin panel fetch error:', err);
    }
}

// Test Admin Route from Normal User perspective (Demonstrating 403 Forbidden)
testAdminRouteBtn.addEventListener('click', async () => {
    const token = sessionStorage.getItem(TOKEN_STORAGE_KEY);
    testAdminRouteBtn.disabled = true;
    testAdminRouteBtn.textContent = 'Sending Request to GET /api/admin...';

    try {
        const response = await fetch(`${API_BASE}/admin`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const data = await response.json();

        adminTestResult.classList.remove('hidden');
        if (response.status === 403) {
            testResultBadge.textContent = `HTTP ${response.status} Forbidden (RBAC Enforced)`;
            testResultBadge.className = 'status-pill pill-danger';
        } else {
            testResultBadge.textContent = `HTTP ${response.status}`;
            testResultBadge.className = 'status-pill pill-warning';
        }

        testResultBody.textContent = JSON.stringify({
            httpStatus: response.status,
            statusText: response.statusText,
            headers: {
                'Content-Type': response.headers.get('content-type')
            },
            responsePayload: data
        }, null, 2);

    } catch (err) {
        console.error('Test route error:', err);
        testResultBody.textContent = 'Network error during request.';
    } finally {
        testAdminRouteBtn.disabled = false;
        testAdminRouteBtn.textContent = '⚡ Test Access to GET /api/admin (Demonstrate 403 Forbidden)';
    }
});

// Load Security Recommendations
async function loadSecurityRecommendations() {
    try {
        const response = await fetch(`${API_BASE}/security`);
        const result = await response.json();

        if (response.ok && result.success) {
            recommendationsContainer.innerHTML = '';

            result.recommendations.forEach(rec => {
                const card = document.createElement('div');
                card.className = 'rec-card';
                card.innerHTML = `
                    <div class="rec-card-header">
                        <h4 class="rec-title">${escapeHtml(rec.title)}</h4>
                        <span class="rec-category">${escapeHtml(rec.category)}</span>
                    </div>
                    <p class="rec-desc">${escapeHtml(rec.description)}</p>
                `;
                recommendationsContainer.appendChild(card);
            });
        }
    } catch (err) {
        console.error('Failed to load security recommendations:', err);
    }
}

// ==========================================
// LOGOUT & SESSION RESET
// ==========================================

function handleLogout(message = 'You have been successfully logged out.') {
    sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    sessionStorage.removeItem(USER_STORAGE_KEY);
    showAuthView();
    if (message) {
        showAlert(message, 'warning');
    }
}

logoutBtn.addEventListener('click', () => {
    handleLogout();
});

function showAuthView() {
    dashboardView.classList.add('hidden');
    navUserControls.classList.add('hidden');
    authView.classList.remove('hidden');
    showLoginTab();
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ==========================================
// INITIALIZATION ON PAGE LOAD
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
    const existingToken = sessionStorage.getItem(TOKEN_STORAGE_KEY);
    if (existingToken) {
        loadDashboard();
    } else {
        showAuthView();
    }
});
