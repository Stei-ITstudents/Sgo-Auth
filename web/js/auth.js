document.addEventListener("DOMContentLoaded", () => {
  const container = document.querySelector(".container");

  container.addEventListener("mouseenter", function () {
    document.body.classList.add("hover-disabled");
  });

  container.addEventListener("mouseleave", function () {
    document.body.classList.remove("hover-disabled");
  });
});

document.addEventListener("DOMContentLoaded", () => {
  const togglePassword = document.getElementById("togglePassword");
  const passwordInput = document.getElementById("password");

  togglePassword.addEventListener("click", () => {
    if (passwordInput.type === "password") {
      passwordInput.type = "text";
      togglePassword.textContent = "👁️"; // Change icon to indicate hiding
    } else {
      passwordInput.type = "password";
      togglePassword.textContent = "🙈"; // Change icon to indicate showing
    }
  });
});

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
        logMessage.textContent = `Added ID: ${data.id} - ${data.email}`;
        logMessage.style.display = "block"; // Show log message
      }
    })
    .catch((error) => {
      console.error("Error:", error);
      logMessage.textContent = `Error: ${error.message}`; // Update on error
      logMessage.style.display = "block"; // Show log message
      logMessage.style.backgroundColor = "#a103038e";
    });
});