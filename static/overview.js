async function fetchJSON(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    let message = response.statusText;
    try {
      const data = await response.json();
      if (data.error) {
        message = data.error;
      }
    } catch (e) {}
    throw new Error(message);
  }
  return response.json();
}

function setOverviewStatus(message, isError = false) {
  const status = document.getElementById("overview-status");
  status.textContent = message || "";
  status.style.color = isError ? "#b42318" : "#555";
}

async function loadExecutiveSummary() {
  try {
    const data = await fetchJSON("/api/overview/executive-summary");
    document.getElementById("executive-summary-editor").value = data.content || "";
    setOverviewStatus("");
  } catch (e) {
    setOverviewStatus(e.message, true);
  }
}

async function saveExecutiveSummary() {
  const editor = document.getElementById("executive-summary-editor");
  const saveButton = document.getElementById("save-executive-summary");

  saveButton.disabled = true;
  saveButton.textContent = "Saving...";

  try {
    await fetchJSON("/api/overview/executive-summary", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: editor.value })
    });
    setOverviewStatus("Executive summary saved");
  } catch (e) {
    setOverviewStatus(e.message, true);
  } finally {
    saveButton.disabled = false;
    saveButton.textContent = "Save Executive Summary";
  }
}

window.addEventListener("DOMContentLoaded", () => {
  document
    .getElementById("save-executive-summary")
    .addEventListener("click", saveExecutiveSummary);

  loadExecutiveSummary();
});
