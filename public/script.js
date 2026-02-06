document.addEventListener("DOMContentLoaded", function() {
    const loginBtn = document.getElementById("loginBtn");
    const signupBtn = document.getElementById("signupBtn");
    const loginForm = document.getElementById("loginForm");
    const signupForm = document.getElementById("signupForm");

    // Toggle Logic
    loginBtn.addEventListener("click", () => {
        loginBtn.classList.add("active");
        signupBtn.classList.remove("active");
        loginForm.classList.add("active");
        signupForm.classList.remove("active");
    });

    signupBtn.addEventListener("click", () => {
        signupBtn.classList.add("active");
        loginBtn.classList.remove("active");
        signupForm.classList.add("active");
        loginForm.classList.remove("active");
    });

    // ------------------------------------------
    // HANDLE SIGNUP FORM SUBMISSION
    // ------------------------------------------
    signupForm.addEventListener("submit", async (e) => {
        e.preventDefault(); // Stop page reload

        const name = signupForm.querySelector('input[type="text"]').value;
        const email = signupForm.querySelector('input[type="email"]').value;
        const password = signupForm.querySelector('input[type="password"]').value;

        try {
            const response = await fetch('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, email, password })
            });

            const data = await response.json();
            
            if (data.success) {
                alert("Account Created! Redirecting...");
                window.location.href = "/dashboard";
            } else {
                alert("Error: " + data.error);
            }
        } catch (error) {
            console.error("Signup Error:", error);
        }
    });

    // ------------------------------------------
    // HANDLE LOGIN FORM SUBMISSION
    // ------------------------------------------
    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();

        const email = loginForm.querySelector('input[type="email"]').value;
        const password = loginForm.querySelector('input[type="password"]').value;

        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (data.success) {
                window.location.href = "/dashboard";
            } else {
                alert("Login Failed: " + data.error);
            }
        } catch (error) {
            console.error("Login Error:", error);
        }
    });
});