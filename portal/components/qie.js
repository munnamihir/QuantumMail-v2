window.addEventListener("DOMContentLoaded", function () {

  console.log("QIE loaded");

  // Create button
  const button = document.createElement("div");
  button.id = "qie-button";
  button.innerHTML = "⚡";
  document.body.appendChild(button);

  // Create popup
  const popup = document.createElement("div");
  popup.id = "qie-popup";

  popup.innerHTML = `
    <div id="qie-header">
      QuantumMail Intelligence Engine
      <span id="qie-close">×</span>
    </div>

    <div id="qie-messages"></div>

    <div id="qie-input-area">
      <input id="qie-input" placeholder="Ask QIE..." />
      <button id="qie-send">Ask</button>
    </div>
  `;

  document.body.appendChild(popup);

  // FORCE hidden initially
  popup.style.display = "none";

  // Toggle open
  button.onclick = () => {
    popup.style.display = "flex";
  };

  // Close
  document.addEventListener("click", function (e) {
    if (e.target.id === "qie-close") {
      popup.style.display = "none";
    }
  });

  // Ask AI
  document.addEventListener("click", async function (e) {
    if (e.target.id === "qie-send") {

      const input = document.getElementById("qie-input");
      const msgBox = document.getElementById("qie-messages");

      const question = input.value;

      if (!question) return;

      msgBox.innerHTML += `<div><b>You:</b> ${question}</div>`;

      const res = await fetch("/qie/query", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ question })
      });

      const data = await res.json();

      msgBox.innerHTML += `<div style="color:#93c5fd"><b>QIE:</b> ${data.answer}</div>`;

      input.value = "";
    }
  });

});
