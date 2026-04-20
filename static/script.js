// GET ELEMENTS
const form = document.getElementById("scanForm");
const loader = document.getElementById("loader");
const toggleBtn = document.getElementById("themeToggle");

// LOADER (SAFE CHECK)
if (form && loader) {
    form.addEventListener("submit", function () {
        loader.classList.remove("hidden");
    });
}

// THEME TOGGLE
if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
        document.body.classList.toggle("light-mode");

        if (document.body.classList.contains("light-mode")) {
            localStorage.setItem("theme", "light");
        } else {
            localStorage.setItem("theme", "dark");
        }

        updateButtonText();
    });
}

// LOAD SAVED THEME
window.addEventListener("DOMContentLoaded", () => {
    const savedTheme = localStorage.getItem("theme");

    if (savedTheme === "light") {
        document.body.classList.add("light-mode");
    }

    updateButtonText();
});

// UPDATE BUTTON TEXT
function updateButtonText() {
    if (!toggleBtn) return;

    if (document.body.classList.contains("light-mode")) {
        toggleBtn.innerText = "☀️ Light Mode";
    } else {
        toggleBtn.innerText = "🌙 Dark Mode";
    }
}