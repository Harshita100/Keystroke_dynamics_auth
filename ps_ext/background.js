chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "save_password") {
      fetch("http://127.0.0.1:5000/save_password", {  // Local Flask API
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: request.password })
      })
      .then(response => response.json())
      .then(data => console.log("Backend response:", data))
      .catch(error => console.error("Error sending password:", error));
  }
});
