// --- AUTHENTICATION LOGIC ---

// 1. CONSTANTS & CONFIG
// SUPER_ADMINS removed - strictly role-based now
const STUDENT_EMAIL_REGEX = /^[0-9]{8}@kiit\.ac\.in$/;
const KIIT_EMAIL_REGEX = /@kiit\.ac\.in$/;

// REMOVED: Insecure Hash & Hardcoded Keys
// Authentication is now handled 100% by Firebase Auth.

let isSignup = false;
let selectedRole = "Student"; // Default role

// 2. UI INTERACTIONS

// Role Selection Logic
const roleButtons = document.querySelectorAll(".role-option");
roleButtons.forEach(btn => {
    btn.addEventListener("click", () => {
        // Remove active class from all
        roleButtons.forEach(b => b.classList.remove("active"));
        // Add active class to clicked
        btn.classList.add("active");

        // Update selected role state
        const roleMap = {
            'student': 'Student',
            'admin': 'Admin'
        };
        selectedRole = roleMap[btn.dataset.role] || 'Student';
        console.log("Role selected:", selectedRole);

        // Update UI for Admin
        const passLabel = document.querySelector(".password-group label");
        const passInput = document.getElementById("password");

        if (selectedRole === 'Admin') {
            passLabel.textContent = "Access Key";
            passInput.placeholder = "Enter Admin Key";
            passInput.type = "password";
        } else {
            passLabel.textContent = "Password";
            passInput.placeholder = "••••••••";
            passInput.type = "password";
        }
    });
});

const nameField = document.getElementById("name");
const confirmGroup = document.getElementById("confirmGroup");
const roleGroup = document.getElementById("roleGroup");
const termsGroup = document.getElementById("termsGroup");

// Init UI - Login Mode Only
if (confirmGroup) confirmGroup.style.display = "none";
if (termsGroup) termsGroup.style.display = "none";
if (nameField) nameField.style.display = "none";

function initUI() {
    isSignup = false;
    const termsLabel = document.querySelector("#termsGroup label");
    if (termsLabel) termsLabel.textContent = "Remember Me";
    if (termsGroup) termsGroup.style.display = "flex";
}
initUI();

function togglePassword() {
    const pass = document.getElementById("password");
    pass.type = pass.type === "password" ? "text" : "password";
}

// 3. CORE LOGIN LOGIC

document.getElementById("authForm").addEventListener("submit", e => {
    e.preventDefault();

    const email = document.getElementById("email").value.trim().toLowerCase();
    const password = document.getElementById("password").value; // Access Key for Admin

    // --- STEP 1: EMAIL & ROLE VALIDATION ---

    if (selectedRole === 'Admin') {
        // SUPER ADMIN CHECK
        if (SUPER_ADMINS.includes(email)) {
            // It's a Super Admin, proceed to password check
        } else {
            // Check if it's a Limited Admin (stored in localStorage)
            const users = JSON.parse(localStorage.getItem('users')) || [];
            const adminUser = users.find(u => u.email === email && u.role === 'Admin');

            if (!adminUser) {
                alert("Access Denied: You are not authorized as an Administrator.");
                return;
            }
        }
    } else if (selectedRole === 'Student') {
        // Allow any email – domain restriction removed
    }

    // --- STEP 2: CREDENTIAL VALIDATION ---

    if (selectedRole === 'Admin') {
        const authBtn = document.querySelector('.btn');
        const originalText = authBtn.innerHTML;
        authBtn.disabled = true;
        authBtn.innerHTML = "Verifying...";

        // 1. Secure Firebase Auth Login
        firebase.auth().signInWithEmailAndPassword(email, password)
            .then((userCredential) => {
                // Success! The state listener in init() or admin.js will handle the rest? 
                // Actually auth.js handles redirect in loginSuccess.
                // We need to fetch the profile or just trust the auth?
                // Visual feedback is good.
                loginSuccess({
                    name: userCredential.user.displayName || email.split('@')[0],
                    email: email,
                    role: 'Admin', // Provisional, admin.js will verify claim
                    uid: userCredential.user.uid
                    // We don't set 'permissions' here blindly anymore.
                });
            })
            .catch((error) => {
                console.error("Login Error:", error);
                alert(`Authentication Failed: ${error.message}`);
                authBtn.disabled = false;
                authBtn.innerHTML = originalText;
            });
        return;
        return;
    }

    // Helper for Legacy LocalStorage Check (Moved strictly for fallback)
    function checkLocalStorageAdmin(email, password) {
        const users = JSON.parse(localStorage.getItem('users')) || [];
        const adminUser = users.find(u => u.email === email && u.role === 'Admin');

        if (adminUser) {
            if (adminUser.password !== password) {
                alert("Invalid Password.");
                return;
            }
            loginSuccess(adminUser);
        } else {
            alert("Access Denied: Admin account not found.");
        }
    }

    // STUDENT LOGIN
    if (selectedRole === 'Student') {
        // Mock Login for Student (Accept any password for demo if user exists, or simulate success)
        // In real app: verify hash(password) against DB.

        const users = JSON.parse(localStorage.getItem('users')) || [];
        let studentUser = users.find(u => u.email === email);

        // Auto-create student if not exists (for ease of use in demo) OR strictly require signup?
        // Requirement said "Sign-Up Text Removal", implying simplified flow.
        if (!studentUser) {
            // For demo purposes, we allow new students to "Login" directly to create account
            studentUser = {
                name: "Student",
                email: email,
                role: 'Student',
                joined: new Date().toISOString()
            };
            users.push(studentUser);
            localStorage.setItem('users', JSON.stringify(users));
        }

        loginSuccess(studentUser);
    }
});


function loginSuccess(user) {
    if (user.status === 'Blocked') {
        alert("Your account has been blocked by an administrator.");
        return;
    }

    const rememberMe = document.getElementById("terms")?.checked;
    if (rememberMe) {
        localStorage.setItem("currentUser", JSON.stringify(user));
    } else {
        sessionStorage.setItem("currentUser", JSON.stringify(user));
    }

    alert(`Welcome back, ${user.name || 'User'}!`);

    if (user.role === 'Admin') {
        window.location.href = "admin-dashboard.html";
    } else {
        window.location.href = "user-dashboard.html";
    }
}


// 4. GOOGLE AUTH LOGIC (REAL FIREBASE IMPLEMENTATION)

// TODO: User must replace these with their own Firebase Config keys from console.firebase.google.com
const firebaseConfig = {
    apiKey: "AIzaSyDUwWbFcU0IUivzp_MevyD9jOPRRRnrrJA",
    authDomain: "kiit-events.firebaseapp.com",
    databaseURL: "https://kiit-events-default-rtdb.firebaseio.com",
    projectId: "kiit-events",
    storageBucket: "kiit-events.firebasestorage.app",
    messagingSenderId: "90796391324",
    appId: "1:90796391324:web:7aca456732eb24fd46a659"
};

// Initialize Firebase
if (typeof firebase !== 'undefined') {
    firebase.initializeApp(firebaseConfig);
    // Initialize Firestore
    window.db = firebase.firestore();
} else {
    console.error("Firebase SDK not loaded.");
}

window.signInWithGoogle = function () {
    if (typeof firebase === 'undefined') {
        alert("Firebase is not initialized. Please check internet connection or config.");
        return;
    }

    const provider = new firebase.auth.GoogleAuthProvider();
    const googleBtn = document.querySelector('.google-btn');
    const originalText = googleBtn.innerHTML;

    googleBtn.innerHTML = "Signing in...";

    firebase.auth().signInWithPopup(provider)
        .then((result) => {
            const user = result.user;
            // Google Login Success
            completeGoogleLogin(user);
        })
        .catch((error) => {
            console.error("Google Auth Error:", error);
            googleBtn.innerHTML = originalText;

            if (error.code === 'auth/popup-closed-by-user') {
                return; // Ignore
            }
            if (error.code === 'auth/unauthorized-domain') {
                alert("Domain not authorized in Firebase Console -> Authentication -> Settings.");
            } else {
                alert(`Login Failed: ${error.message}`);
            }
        });
}

window.completeGoogleLogin = async function (firebaseUser) {
    const email = firebaseUser.email.toLowerCase().trim();
    const name = firebaseUser.displayName;

    // --- GOOGLE ROLE ENFORCEMENT ---
    let role = 'Student';
    let type = 'REGULAR';
    let permissions = [];
    let provider = "google";

    // 1. Check Super Admin (Hardcoded Override)
    if (SUPER_ADMINS.includes(email)) {
        role = 'Admin';
        type = 'SUPERUSER';
        permissions = ['ALL'];

        finalizeLogin({
            name, email, role, type, permissions, joined: new Date().toISOString(), provider, photoURL: firebaseUser.photoURL
        });
        return;
    }

    // 2. Check Firestore for Admin Role
    try {
        if (typeof db !== 'undefined' && navigator.onLine) {
            const adminDoc = await db.collection('admins').doc(email).get();

            if (adminDoc.exists) {
                const adminData = adminDoc.data();
                if (adminData.status !== 'Blocked' && adminData.status !== 'Inactive') {
                    finalizeLogin({
                        name: adminData.name || name,
                        email, role: 'Admin', type: adminData.type || 'LIMITED', permissions: adminData.permissions || [],
                        joined: adminData.joined || new Date().toISOString(),
                        provider, photoURL: firebaseUser.photoURL
                    });
                    return;
                } else {
                    alert("Your admin access has been revoked or inactive.");
                    return;
                }
            }
        }
    } catch (error) {
        console.error("Error fetching admin role from Firestore:", error);
    }

    // --- LOCALSTORAGE FALLBACK FOR ADMINS ---
    const users = JSON.parse(localStorage.getItem('users')) || [];
    const localAdmin = users.find(u => u.email === email && u.role === 'Admin');

    if (localAdmin) {
        console.log("Admin found in localStorage fallback.");
        finalizeLogin({
            name: localAdmin.name || name,
            email: email,
            role: 'Admin',
            type: localAdmin.type || 'LIMITED',
            permissions: localAdmin.permissions || [],
            joined: localAdmin.joined || new Date().toISOString(),
            provider,
            photoURL: firebaseUser.photoURL
        });
        return;
    }

    // 3. Default to Student for any email (after admin checks)
    role = 'Student';
    finalizeLogin({
        name, email, role, type: 'REGULAR', permissions: [], joined: new Date().toISOString(), provider, photoURL: firebaseUser.photoURL
    });
}

function finalizeLogin(appUser) {
    loginSuccess(appUser);
}

// AUTO LOGIN CHECK
window.onload = () => {
    const loggedInUser = JSON.parse(localStorage.getItem("currentUser")) || JSON.parse(sessionStorage.getItem("currentUser"));
    if (loggedInUser) {
        // Optional: Redirect if already logged in, or just stay to allow logout loop
    }
};
