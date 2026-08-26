(() => {
  const form = document.querySelector("[data-questionnaire-form]");
  if (!form) return;

  const csrfToken = form.querySelector('input[name="csrf_token"]')?.value || "";
  const revisionField = form.querySelector('input[name="revision"]');
  const statusField = document.querySelector("[data-save-status]");
  const dirty = new Set();
  const queued = new Set();
  const timers = new Map();
  let pumpPromise = null;

  function setSaveStatus(message, isError = false) {
    if (!statusField) return;
    statusField.textContent = message;
    statusField.closest(".save-status")?.toggleAttribute("data-error", isError);
  }

  function cardFor(key) {
    return form.querySelector(`[data-question-key="${key}"]`);
  }

  function answerFor(card) {
    const fields = [...card.querySelectorAll("[data-answer-field]")];
    const type = card.dataset.questionType;
    let value;
    if (type === "single_choice") {
      value = fields.find((field) => field.checked)?.value || null;
    } else if (type === "multi_choice") {
      value = fields.filter((field) => field.checked).map((field) => field.value);
    } else {
      value = fields[0]?.value ?? "";
      if (type === "number" || type === "scale") {
        value = value === "" ? null : Number(value);
      }
    }

    const required = fields.some((field) => field.required);
    if ((value === null || value === "" || (Array.isArray(value) && value.length === 0)) && !required) {
      return null;
    }
    const answer = { value };
    if (card.dataset.commentEnabled === "true") {
      answer.comment = card.querySelector("[data-comment-field]")?.value || "";
    }
    return answer;
  }

  function queueCard(card) {
    const key = card?.dataset.questionKey;
    if (!key) return;
    dirty.add(key);
    queued.add(key);
    void pumpSaves();
  }

  function debounceCard(card) {
    const key = card?.dataset.questionKey;
    if (!key) return;
    dirty.add(key);
    window.clearTimeout(timers.get(key));
    timers.set(key, window.setTimeout(() => queueCard(card), 700));
  }

  async function saveCard(key) {
    const response = await fetch(`/answers/${encodeURIComponent(key)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      body: JSON.stringify({ revision: Number(revisionField?.value || 0), answer: answerFor(cardFor(key)) }),
    });
    let body = {};
    try {
      body = await response.json();
    } catch (_) {
      body = {};
    }
    if (!response.ok) {
      if (response.status === 409 && Number.isInteger(body.current_revision)) {
        revisionField.value = String(body.current_revision);
        setSaveStatus("Ответы обновились — обновите страницу", true);
      } else {
        setSaveStatus("Не удалось сохранить — повторить", true);
      }
      return false;
    }
    revisionField.value = String(body.revision);
    if (!queued.has(key)) dirty.delete(key);
    setSaveStatus("Сохранено");
    return true;
  }

  async function pumpSaves() {
    if (pumpPromise) return pumpPromise;
    pumpPromise = (async () => {
      let allSaved = true;
      while (queued.size > 0) {
        const key = queued.values().next().value;
        queued.delete(key);
        try {
          if (!(await saveCard(key))) allSaved = false;
        } catch (_) {
          setSaveStatus("Не удалось сохранить — повторить", true);
          allSaved = false;
        }
      }
      return allSaved;
    })().finally(() => {
      pumpPromise = null;
    });
    return pumpPromise;
  }

  async function flushDirty() {
    timers.forEach((timer, key) => {
      window.clearTimeout(timer);
      queueCard(cardFor(key));
    });
    timers.clear();
    dirty.forEach((key) => queued.add(key));
    return pumpSaves();
  }

  form.querySelectorAll("[data-answer-field], [data-comment-field]").forEach((field) => {
    const card = field.closest("[data-question-key]");
    field.addEventListener("input", () => debounceCard(card));
    field.addEventListener("change", () => queueCard(card));
    field.addEventListener("blur", () => window.setTimeout(() => queueCard(card), 0));
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!(await flushDirty())) return;
    HTMLFormElement.prototype.submit.call(form);
  });

  async function apiRequest(path, options = {}) {
    const headers = {
      Accept: "application/json",
      "X-CSRF-Token": csrfToken,
      ...(options.headers || {}),
    };
    const response = await fetch(path, { ...options, headers });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.detail || "request failed");
    return body;
  }

  function addDeleteButton(line, documentId) {
    const button = document.createElement("button");
    button.className = "primary-button";
    button.type = "button";
    button.textContent = "Удалить";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await apiRequest(`/documents/${encodeURIComponent(documentId)}`, { method: "DELETE" });
        line.textContent = `${line.dataset.filename}: Файл удалён`;
      } catch (_) {
        button.disabled = false;
        line.textContent = `${line.dataset.filename}: Не удалось удалить`;
        line.append(" ", button);
      }
    });
    line.append(" ", button);
  }

  async function uploadFile(file, list, status) {
    const line = document.createElement("p");
    line.className = "question-helper";
    line.dataset.filename = file.name;
    line.textContent = `${file.name}: загружаем…`;
    list.append(line);
    try {
      const intent = await apiRequest("/documents/uploads", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ original_name: file.name, declared_mime: file.type, size_bytes: file.size }),
      });
      const upload = await fetch(intent.upload_url, {
        method: "PUT",
        headers: { "Content-Type": file.type },
        body: file,
      });
      if (!upload.ok) throw new Error("upload failed");
      const completed = await apiRequest(`/documents/${encodeURIComponent(intent.document_id)}/complete`, {
        method: "POST",
      });
      line.textContent = `${file.name}: ${completed.status === "quarantined" ? "проверяем файл…" : completed.status}`;
      addDeleteButton(line, intent.document_id);
      status.textContent = "Файл добавлен и отправлен на проверку";
    } catch (_) {
      line.textContent = `${file.name}: не удалось загрузить, попробуйте ещё раз`;
      status.textContent = "Есть файл, который не удалось загрузить";
    }
  }

  form.querySelectorAll("[data-document-input]").forEach((input) => {
    input.addEventListener("change", async () => {
      const card = input.closest("[data-question-key]");
      const list = card.querySelector("[data-upload-list]");
      const status = card.querySelector("[data-upload-status]");
      const files = [...input.files].slice(0, 10);
      if (input.files.length > 10) status.textContent = "Можно выбрать не больше 10 файлов за раз";
      for (const file of files) await uploadFile(file, list, status);
      input.value = "";
    });
  });
})();
