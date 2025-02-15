chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "update_ui") {
      document.getElementById("status").innerText = request.feedback;
  }
});
