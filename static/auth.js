(() => {
  const form = document.querySelector("[data-magic-form]");
  if (!form) return;

  const token = new URLSearchParams(window.location.hash.slice(1)).get("token");
  window.history.replaceState(null, document.title, window.location.pathname);
  if (!token) {
    const status = document.querySelector("[data-magic-status]");
    if (status) status.textContent = "Ссылка недействительна или уже использована.";
    return;
  }

  form.querySelector("[name=token]").value = token;
  form.submit();
})();
