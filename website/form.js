/*
 * Feedback form. The form is a normal HTML form that posts to /api/feedback and works without this
 * file (the function redirects back with ?feedback=sent or ?feedback=error). With JavaScript the
 * submission stays on the page and the result is announced in the status line.
 */
(() => {
  const form = document.getElementById("feedback-form");
  const status = document.getElementById("feedback-status");
  if (!form || !status) return;

  const show = (message, kind) => {
    status.textContent = message;
    status.dataset.kind = kind;
  };

  // The no-JS path lands here after a redirect.
  const result = new URLSearchParams(window.location.search).get("feedback");
  if (result === "sent") show("Thank you. Your message was received.", "ok");
  if (result === "error") show("The message could not be sent. Check the fields and try again, or open an issue on GitHub.", "error");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    show("Sending…", "pending");
    try {
      const data = Object.fromEntries(new FormData(form).entries());
      const response = await fetch(form.action, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(data),
      });
      const body = await response.json().catch(() => ({}));
      if (response.ok && body.ok) {
        form.reset();
        show("Thank you. Your message was received.", "ok");
      } else {
        show(body.error || "The message could not be sent. Please try again later.", "error");
      }
    } catch {
      show("The message could not be sent. Check your connection and try again.", "error");
    } finally {
      button.disabled = false;
    }
  });
})();
