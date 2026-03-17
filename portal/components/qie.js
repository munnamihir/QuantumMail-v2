const button = document.createElement("div");

button.id = "qie-button";
button.innerText = "QIE";

document.body.appendChild(button);

const button = document.getElementById("qie-button");
const popup = document.getElementById("qie-popup");
const close = document.getElementById("qie-close");

button.onclick = () => {
  popup.style.display = "flex";
};

close.onclick = () => {
  popup.style.display = "none";
};

popup.id = "qie-popup";

popup.innerHTML = `
<div class="qie-header">QuantumMail Intelligence Engine</div>
<div id="qie-messages"></div>
<input id="qie-input" placeholder="Ask QIE..." />
<button id="qie-send">Ask</button>
`;

document.body.appendChild(popup);

button.onclick = () => {
  popup.style.display =
    popup.style.display === "block"
      ? "none"
      : "block";
};

document.getElementById("qie-send").onclick = askQIE;

async function askQIE(){

  const question =
    document.getElementById("qie-input").value;

  const res = await fetch("/qie/query", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ question })
  });

  const data = await res.json();

  const div =
    document.getElementById("qie-messages");

  div.innerHTML += `<p><b>You:</b> ${question}</p>`;
  div.innerHTML += `<p><b>QIE:</b> ${data.answer}</p>`;

}
