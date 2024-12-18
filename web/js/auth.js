document.addEventListener("DOMContentLoaded", () => {
  const container = document.querySelector(".container");
  const togglePassword = document.getElementById("togglePassword");
  const passwordInput = document.getElementById("password");
  const authForm = document.getElementById("authForm");
  const usernameField = document.getElementById("usernameField");
  const rememberForgot = document.getElementById("rememberForgot");
  const submitBtn = authForm.querySelector(".submit-btn");
  const switchFormBtn = document.getElementById("switchFormBtn");
  const logMessage = document.getElementById("LogMessage");
  const formTitle = document.getElementById("formTitle");

  let isLogin = true;

  // Hover logic
  container.addEventListener("mouseenter", () => {
    document.body.classList.add("hover-disabled");
  });

  container.addEventListener("mouseleave", () => {
    document.body.classList.remove("hover-disabled");
  });

  // Password toggle logic
  togglePassword.addEventListener("click", () => {
    if (passwordInput.type === "password") {
      passwordInput.type = "text";
      togglePassword.textContent = "👁️";
    } else {
      passwordInput.type = "password";
      togglePassword.textContent = "🙈";
    }
  });

  // Form switch logic
  switchFormBtn.addEventListener("click", () => {
    isLogin = !isLogin;
    if (isLogin) {
      formTitle.textContent = "Login";
      usernameField.style.display = "none";
      rememberForgot.style.display = "flex";
      submitBtn.textContent = "Login";
      switchFormBtn.textContent = "Don't have an account? Register";
    } else {
      formTitle.textContent = "Register";
      usernameField.style.display = "block";
      rememberForgot.style.display = "none";
      submitBtn.textContent = "Register";
      switchFormBtn.textContent = "Already have an account? Login";
    }
  });

  // Authentication form submission logic
  authForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = isLogin ? "/login" : "/register";
    const formData = new FormData(authForm);
    const jsonData = {};
    formData.forEach((value, key) => {
      jsonData[key] = value;
    });

    fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(jsonData),
    })
      .then((response) => {
        if (!response.ok) {
          return response.json().then((data) => {
            throw new Error(data.error || "Unknown error");
          });
        }
        return response.json();
      })
      .then((data) => {
        if (data.redirect) {
          window.location.href = data.redirect;
        } else {
          logMessage.style.backgroundColor = "#030ea183";
          logMessage.textContent = `Added: ${data.email}`;
          logMessage.style.display = "block";
        }
      })
      .catch((error) => {
        console.error("Error:", error);
        logMessage.textContent = `Error: ${error.message}`;
        logMessage.style.display = "block";
        logMessage.style.backgroundColor = "#a103038e";
      });
  });

  // Logout function
  async function logout() {
    try {
      const response = await fetch("http://localhost:8000/logout", {
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        method: "POST",
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Unknown error");
      }

      const data = await response.json();
      console.log("Logout successful:", data);
      // Make sure the page reload happens after the logout response
      window.location.href = "/auth";
    } catch (error) {
      console.error("Error during logout:", error);
    }
  }

  // Attach logout function to logout button
  document.getElementById("logoutBtn").addEventListener("click", logout);
});
