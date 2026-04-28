(function () {
  "use strict";

  var THEME_KEY = "spamshield-theme";

  function getStoredTheme() {
    return localStorage.getItem(THEME_KEY) || "light";
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem(THEME_KEY, theme);
  }

  function initTheme() {
    applyTheme(getStoredTheme());
    document.querySelectorAll("#theme-toggle").forEach(function (toggle) {
      toggle.addEventListener("click", function () {
        var next =
          document.documentElement.getAttribute("data-theme") === "dark"
            ? "light"
            : "dark";
        applyTheme(next);
      });
    });
  }

  function createRipple(button, event) {
    var circle = document.createElement("span");
    circle.className = "ripple-circle";
    var rect = button.getBoundingClientRect();
    var size = Math.max(rect.width, rect.height);
    circle.style.width = circle.style.height = size + "px";
    circle.style.left = event.clientX - rect.left - size / 2 + "px";
    circle.style.top = event.clientY - rect.top - size / 2 + "px";
    button.appendChild(circle);
    circle.addEventListener("animationend", function () {
      circle.remove();
    });
  }

  function initRipples() {
    document.querySelectorAll(".btn-ripple").forEach(function (btn) {
      btn.addEventListener("click", function (e) {
        createRipple(btn, e);
      });
    });
  }

  function showLoading(show) {
    var overlay = document.getElementById("loading-overlay");
    if (!overlay) return;
    overlay.classList.toggle("is-visible", !!show);
    overlay.setAttribute("aria-hidden", show ? "false" : "true");
  }

  function initSidebar() {
    var sidebar = document.getElementById("sidebar");
    var toggle = document.getElementById("menu-toggle");
    var backdrop = document.getElementById("sidebar-backdrop");
    if (!sidebar || !toggle) return;

    function close() {
      sidebar.classList.remove("is-open");
      if (backdrop) backdrop.classList.remove("is-visible");
      document.body.classList.remove("sidebar-open");
    }

    function open() {
      sidebar.classList.add("is-open");
      if (backdrop) backdrop.classList.add("is-visible");
      document.body.classList.add("sidebar-open");
    }

    toggle.addEventListener("click", function () {
      if (sidebar.classList.contains("is-open")) close();
      else open();
    });
    if (backdrop) {
      backdrop.addEventListener("click", close);
    }
    window.addEventListener("resize", function () {
      if (window.innerWidth > 900) close();
    });
  }

  function initProfileMenu() {
    var trigger = document.getElementById("profile-trigger");
    var menu = document.getElementById("profile-dropdown");
    if (!trigger || !menu) return;

    function close() {
      menu.hidden = true;
      trigger.setAttribute("aria-expanded", "false");
    }

    function open() {
      menu.hidden = false;
      trigger.setAttribute("aria-expanded", "true");
    }

    trigger.addEventListener("click", function (e) {
      e.stopPropagation();
      if (menu.hidden) open();
      else close();
    });

    document.addEventListener("click", function (e) {
      if (!menu.hidden && !menu.contains(e.target) && e.target !== trigger) {
        close();
      }
    });
  }

  function escapeHtml(str) {
    if (str == null) return "";
    var d = document.createElement("div");
    d.textContent = str;
    return d.innerHTML;
  }

  function showToast(message, type) {
    var stack = document.getElementById("toast-stack");
    if (!stack) return;
    var t = document.createElement("div");
    t.className = "toast-item toast-" + (type || "info");
    t.textContent = message;
    stack.appendChild(t);
    requestAnimationFrame(function () {
      t.classList.add("is-in");
    });
    setTimeout(function () {
      t.classList.remove("is-in");
      t.classList.add("is-out");
      setTimeout(function () {
        t.remove();
      }, 280);
    }, 4200);
  }
  window.showToast = showToast;

  function renderPrediction(payload) {
    var r = payload.result;
    var mount = document.getElementById("result-mount");
    var panel = document.getElementById("result-panel");
    var placeholder = document.getElementById("result-placeholder");
    if (!mount || !panel) return;

    var verdictClass = r.is_spam ? "verdict-spam" : "verdict-safe";
    var title = r.is_spam ? "Spam Detected" : "Safe Email";
    var icon = r.is_spam ? "❌" : "✅";
    var sub = r.is_spam
      ? "This message tripped the spam model."
      : "No strong spam signal from the model.";

    var rl = (r.risk_level || "Low").toLowerCase();

    var kwHtml = (r.top_keywords || [])
      .map(function (k) {
        return (
          '<span class="keyword-chip">' +
          escapeHtml(k.term) +
          '<span class="keyword-impact">' +
          escapeHtml(String(k.impact)) +
          "</span></span>"
        );
      })
      .join("");

    var whyHtml = (r.why_spam || [])
      .map(function (line) {
        return "<li>" + escapeHtml(line) + "</li>";
      })
      .join("");

    var phishingHtml = "";
    if (r.has_phishing_keywords && r.phishing_hits && r.phishing_hits.length) {
      phishingHtml =
        '<div class="alert-banner alert-phishing" role="alert"><strong>Phishing-style phrases:</strong> ' +
        escapeHtml(r.phishing_hits.join(", ")) +
        '<p class="alert-note">Verify sender and links out-of-band before acting.</p></div>';
    }

    var intelHtml =
      '<div class="intel-strip card-elevated">' +
      '<div class="intel-cols">' +
      '<div class="intel-block"><span class="intel-label">Inbox category</span><span class="badge badge-cat">' +
      escapeHtml(r.category || "—") +
      "</span></div>" +
      '<div class="intel-block"><span class="intel-label">Threat type</span><span class="badge badge-threat">' +
      escapeHtml(r.threat_type || "—") +
      "</span></div>" +
      '<div class="intel-block"><span class="intel-label">Risk level</span><span class="risk-level-pill risk-' +
      escapeHtml(rl) +
      '">' +
      escapeHtml(r.risk_level || "—") +
      "</span></div></div>" +
      '<p class="intel-hint">Threat intelligence uses a dynamic keyword database (phishing / scam / promotion) layered on model scores.</p></div>';

    mount.innerHTML =
      '<div class="verdict-inline ' +
      verdictClass +
      '">' +
      '<span class="verdict-icon" aria-hidden="true">' +
      icon +
      "</span>" +
      "<h2 class=\"verdict-title\">" +
      escapeHtml(title) +
      "</h2>" +
      '<p class="verdict-sub">' +
      escapeHtml(sub) +
      "</p></div>" +
      intelHtml +
      '<div class="metrics-grid">' +
      '<div class="metric-card card-elevated"><span class="metric-label">Confidence</span>' +
      '<span class="metric-value">' +
      escapeHtml(String(r.confidence)) +
      '%</span>' +
      '<div class="progress-track"><div class="progress-fill progress-fill-confidence" style="width:' +
      escapeHtml(String(r.confidence)) +
      '%"></div></div></div>' +
      '<div class="metric-card card-elevated"><span class="metric-label">Spam probability</span>' +
      '<span class="metric-value">' +
      escapeHtml(String(r.spam_probability)) +
      '%</span>' +
      '<div class="progress-track"><div class="progress-fill progress-fill-spam" style="width:' +
      escapeHtml(String(r.spam_probability)) +
      '%"></div></div></div>' +
      '<div class="metric-card card-elevated metric-risk"><span class="metric-label">Risk score</span>' +
      '<div class="metric-value-row"><span class="metric-value">' +
      escapeHtml(String(r.risk_score)) +
      '</span><span class="metric-suffix">/ 100</span></div>' +
      '<div class="progress-track"><div class="progress-fill progress-fill-risk" style="width:' +
      escapeHtml(String(r.risk_score)) +
      '%"></div></div></div></div>' +
      phishingHtml +
      '<div class="explain-card card-elevated"><h3 class="section-heading">Top keywords influencing the score</h3>' +
      '<p class="section-hint">Higher impact means stronger push toward spam in this model (TF-IDF × weights).</p>' +
      '<div class="keyword-chips">' +
      (kwHtml || "<span class=\"muted\">No dominant terms extracted.</span>") +
      "</div></div>" +
      '<div class="explain-card card-elevated"><h3 class="section-heading">Threat & verdict explanation</h3>' +
      "<ul class=\"why-list\">" +
      (whyHtml || "<li>See verdict above.</li>") +
      "</ul></div>" +
      '<div class="body-card card-elevated"><h3 class="section-heading">Highlighted message</h3>' +
      '<p class="section-hint">Spam-correlated tokens (model coefficients) are highlighted.</p>' +
      '<div class="email-body-scroll"><div class="email-body">' +
      r.highlighted_html +
      "</div></div></div>";

    panel.classList.remove("is-hidden");
    if (placeholder) placeholder.classList.add("is-hidden");
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
    showToast("Analysis complete", "success");
    window.lastAnalysisContext = JSON.parse(JSON.stringify(r));
  }

  function updateLocalPreview(text) {
    var body = document.getElementById("preview-body");
    var meta = document.getElementById("preview-meta");
    if (!body || !meta) return;
    var t = (text || "").trim();
    if (!t) {
      meta.textContent = "Type or upload to see a live preview.";
      body.textContent = "";
      return;
    }
    meta.textContent = "Local preview · " + t.length + " characters";
    body.textContent = t.length > 8000 ? t.slice(0, 8000) + "…" : t;
  }

  function initInboxPage() {
    var form = document.getElementById("analyze-form");
    var fileInput = document.getElementById("email_file");
    var uploadBtn = document.getElementById("btn-upload-trigger");
    var previewBtn = document.getElementById("btn-preview-file");
    var textarea = document.getElementById("email_text");
    if (!form) return;

    var debounceTimer;
    if (textarea) {
      textarea.addEventListener("input", function () {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(function () {
          if (!fileInput || !fileInput.files || !fileInput.files.length) {
            updateLocalPreview(textarea.value);
          }
        }, 200);
      });
    }

    if (uploadBtn && fileInput) {
      uploadBtn.addEventListener("click", function () {
        fileInput.click();
      });
    }

    function fetchServerPreview() {
      if (!fileInput || !fileInput.files || !fileInput.files[0]) {
        alert("Choose a .txt or .eml file first.");
        return;
      }
      var fd = new FormData();
      fd.append("email_file", fileInput.files[0]);
      showLoading(true);
      fetch("/api/preview", { method: "POST", body: fd, credentials: "same-origin" })
        .then(function (res) {
          return res.json();
        })
        .then(function (data) {
          showLoading(false);
          if (!data.ok) {
            alert(data.error || "Preview failed");
            return;
          }
          var meta = document.getElementById("preview-meta");
          var body = document.getElementById("preview-body");
          if (meta)
            meta.textContent =
              "Server preview · " +
              data.filename +
              " · " +
              data.length +
              " characters";
          if (body) body.textContent = data.preview || "";
        })
        .catch(function () {
          showLoading(false);
          alert("Network error during preview.");
        });
    }

    if (previewBtn) {
      previewBtn.addEventListener("click", fetchServerPreview);
    }

    if (fileInput) {
      fileInput.addEventListener("change", function () {
        if (fileInput.files && fileInput.files[0]) {
          fetchServerPreview();
        }
      });
    }

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var text = textarea ? textarea.value.trim() : "";
      var hasFile = fileInput && fileInput.files && fileInput.files[0];

      if (!text && !hasFile) {
        alert("Paste email content or upload a file.");
        return;
      }

      var fd = new FormData();
      if (text) fd.append("email_text", text);
      if (hasFile) fd.append("email_file", fileInput.files[0]);

      showLoading(true);
      fetch("/api/predict", { method: "POST", body: fd, credentials: "same-origin" })
        .then(function (res) {
          return res.json().then(function (data) {
            return { ok: res.ok, status: res.status, data: data };
          });
        })
        .then(function (pack) {
          showLoading(false);
          if (!pack.ok || !pack.data.ok) {
            alert((pack.data && pack.data.error) || "Prediction failed");
            return;
          }
          renderPrediction(pack.data);
        })
        .catch(function () {
          showLoading(false);
          showToast("Network error during prediction.", "error");
        });
    });
  }

  function animateCounter(el, target, duration) {
    var start = 0;
    var startTime = null;
    target = parseInt(target, 10) || 0;
    duration = duration || 900;

    function step(ts) {
      if (!startTime) startTime = ts;
      var p = Math.min((ts - startTime) / duration, 1);
      var eased = 1 - Math.pow(1 - p, 3);
      var val = Math.round(start + (target - start) * eased);
      el.textContent = val;
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  function initDashboardCounters() {
    document.querySelectorAll(".stat-number[data-target]").forEach(function (el) {
      animateCounter(el, el.getAttribute("data-target"));
    });
  }

  function initDashboardChart() {
    var canvas = document.getElementById("distribution-chart");
    if (!canvas || typeof Chart === "undefined") return;

    var spam = parseInt(canvas.getAttribute("data-spam"), 10) || 0;
    var ham = parseInt(canvas.getAttribute("data-ham"), 10) || 0;
    var isDark =
      document.documentElement.getAttribute("data-theme") === "dark";
    var textColor = isDark ? "#e8eaed" : "#5f6368";

    if (spam === 0 && ham === 0) {
      var wrap = canvas.parentElement;
      if (wrap) {
        var empty = document.createElement("p");
        empty.className = "chart-empty";
        empty.style.textAlign = "center";
        empty.style.color = textColor;
        empty.style.padding = "2rem";
        empty.textContent = "No analyses yet. Run a check from Inbox.";
        wrap.appendChild(empty);
        canvas.style.display = "none";
      }
      return;
    }

    var ctx = canvas.getContext("2d");
    new Chart(ctx, {
      type: "pie",
      data: {
        labels: ["Spam", "Safe"],
        datasets: [
          {
            data: [spam, ham],
            backgroundColor: ["#ea4335", "#34a853"],
            borderWidth: 2,
            borderColor: isDark ? "#2d2d2d" : "#ffffff",
            hoverOffset: 8,
          },
        ],
      },
      options: {
        responsive: true,
        animation: {
          animateRotate: true,
          animateScale: true,
          duration: 900,
          easing: "easeOutQuart",
        },
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: textColor,
              padding: 16,
              font: { family: "Roboto, sans-serif", size: 13 },
            },
          },
        },
      },
    });
  }

  window.initDashboardChart = initDashboardChart;

  function initUserTrendChart() {
    var canvas = document.getElementById("trend-chart");
    if (!canvas || typeof Chart === "undefined") return;
    var labels = [];
    var counts = [];
    try {
      labels = JSON.parse(canvas.getAttribute("data-labels") || "[]");
      counts = JSON.parse(canvas.getAttribute("data-counts") || "[]");
    } catch (e) {
      return;
    }
    var isDark =
      document.documentElement.getAttribute("data-theme") === "dark";
    var textColor = isDark ? "#e8eaed" : "#5f6368";
    var grid = isDark ? "#444746" : "#e0e0e0";

    if (!labels.length) {
      var w = canvas.parentElement;
      if (w) {
        var empty = document.createElement("p");
        empty.className = "chart-empty";
        empty.style.textAlign = "center";
        empty.style.color = textColor;
        empty.style.padding = "2rem";
        empty.textContent = "No timeline data yet.";
        w.appendChild(empty);
        canvas.style.display = "none";
      }
      return;
    }

    new Chart(canvas.getContext("2d"), {
      type: "line",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Emails analyzed",
            data: counts,
            borderColor: "#1a73e8",
            backgroundColor: "rgba(26,115,232,0.14)",
            fill: true,
            tension: 0.35,
          },
        ],
      },
      options: {
        responsive: true,
        animation: { duration: 800, easing: "easeOutQuart" },
        scales: {
          x: {
            ticks: { color: textColor, maxRotation: 45 },
            grid: { color: grid },
          },
          y: {
            ticks: { color: textColor },
            grid: { color: grid },
            beginAtZero: true,
          },
        },
        plugins: {
          legend: {
            labels: { color: textColor, font: { family: "Roboto, sans-serif" } },
          },
        },
      },
    });
  }

  function setupUserPdfExport() {
    var btn = document.getElementById("btn-user-pdf");
    var root = document.getElementById("user-dashboard-root");
    if (!btn || !root || !window.jspdf) return;
    btn.addEventListener("click", function () {
      var jsPDF = window.jspdf.jsPDF;
      var doc = new jsPDF();
      var y = 18;
      doc.setFontSize(16);
      doc.text("SpamShield AI — Personal analytics", 14, y);
      y += 12;
      doc.setFontSize(10);
      doc.text("Total emails checked: " + (root.dataset.total || "0"), 14, y);
      y += 7;
      doc.text("Spam: " + (root.dataset.spam || "0"), 14, y);
      y += 7;
      doc.text("Safe: " + (root.dataset.safe || "0"), 14, y);
      y += 10;
      doc.text("Generated for workspace export (jsPDF).", 14, y);
      doc.save("spamshield-my-analytics.pdf");
      showToast("PDF report downloaded", "success");
    });
  }

  function setupAdminPdfExport() {
    var btn = document.getElementById("btn-admin-pdf");
    var raw = document.getElementById("admin-pdf-data");
    if (!btn || !raw || !window.jspdf) return;
    btn.addEventListener("click", function () {
      try {
        var data = JSON.parse(raw.textContent || "{}");
        var jsPDF = window.jspdf.jsPDF;
        var doc = new jsPDF();
        var y = 18;
        doc.setFontSize(16);
        doc.text("SpamShield AI — System report", 14, y);
        y += 12;
        doc.setFontSize(10);
        doc.text("Users: " + (data.users != null ? data.users : "—"), 14, y);
        y += 7;
        doc.text("Emails analyzed: " + (data.emails != null ? data.emails : "—"), 14, y);
        y += 7;
        doc.text("Spam: " + (data.spam != null ? data.spam : "—"), 14, y);
        y += 7;
        doc.text("Safe: " + (data.safe != null ? data.safe : "—"), 14, y);
        y += 10;
        doc.text("Includes Chart.js visuals in-app; this PDF is a summary export.", 14, y);
        doc.save("spamshield-system-report.pdf");
        showToast("Admin PDF downloaded", "success");
      } catch (e) {
        showToast("Could not build PDF", "error");
      }
    });
  }

  function scrollChatToBottom() {
    var box = document.getElementById("chat-messages");
    if (!box) return;
    box.scrollTop = box.scrollHeight;
  }

  function appendChatBubble(text, role) {
    var box = document.getElementById("chat-messages");
    if (!box) return null;
    var row = document.createElement("div");
    row.className = "chat-bubble-row chat-" + role;

    var b = document.createElement("div");
    b.className = "chat-bubble";
    b.textContent = text;

    row.appendChild(b);
    box.appendChild(row);
    scrollChatToBottom();
    return b;
  }

  function appendTypingIndicator() {
    var box = document.getElementById("chat-messages");
    if (!box) return null;

    // Typing indicator uses static markup (no user input).
    var row = document.createElement("div");
    row.className = "chat-bubble-row chat-bot chat-typing";

    var b = document.createElement("div");
    b.className = "chat-bubble";
    b.innerHTML =
      'Assistant is typing<span class="typing-dots" aria-hidden="true">' +
      '<span class="typing-dot"></span><span class="typing-dot"></span><span class="typing-dot"></span>' +
      "</span>";

    row.appendChild(b);
    box.appendChild(row);
    scrollChatToBottom();
    return row;
  }

  function initChatWidget() {
    var root = document.getElementById("chat-widget");
    if (!root) return;
    var fab = document.getElementById("chat-fab");
    var panel = document.getElementById("chat-panel");
    var closeBtn = document.getElementById("chat-close");
    var form = document.getElementById("chat-form");
    var input = document.getElementById("chat-input");
    var sendBtn = form ? form.querySelector(".chat-send") : null;
    var opened = false;

    if (panel) {
      panel.hidden = true;
      panel.style.display = "none";
      panel.setAttribute("aria-hidden", "true");
    }

    // Frontend-maintained history for ChatGPT-style follow-ups.
    // Each item is { role: "user"|"assistant", content: "..." }
    var chatHistory = [];
    var typingRow = null;
    var isSending = false;

    function setSendingState(sending) {
      isSending = !!sending;
      if (input) input.disabled = isSending;
      if (sendBtn) sendBtn.disabled = isSending || !((input.value || "").trim().length > 0);
    }

    function updateSendState() {
      if (!sendBtn || isSending) return;
      sendBtn.disabled = !((input.value || "").trim().length > 0);
    }

    function showAssistantGreetingOnce() {
      if (opened) return;
      opened = true;
      var greeting =
        "Hi! Ask me why an email looks spam, what phishing is, explain confidence/risk scores, or how to stay safe.";
      appendChatBubble(greeting, "bot");
      chatHistory.push({ role: "assistant", content: greeting });
    }

    function openPanel() {
      opened = true;
      panel.hidden = false;
      panel.removeAttribute("aria-hidden");
      panel.style.display = "flex";
      fab.setAttribute("aria-expanded", "true");
      root.classList.add("is-open");
      showAssistantGreetingOnce();
      panel.focus();
      input.focus();
    }
    function closePanel() {
      opened = false;
      panel.hidden = true;
      panel.setAttribute("aria-hidden", "true");
      panel.style.display = "none";
      fab.setAttribute("aria-expanded", "false");
      root.classList.remove("is-open");
    }

    fab.addEventListener("click", function () {
      if (!opened) openPanel();
      else closePanel();
    });
    closeBtn.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation();
      closePanel();
    });

    if (input) {
      input.addEventListener("input", updateSendState);
      updateSendState();
    }

    // Ensure pressing Enter doesn't submit an empty message.
    if (form) {
      form.addEventListener("submit", function (e) {
        e.preventDefault();
        var msg = (input.value || "").trim();
        if (!msg) return;
        if (isSending) return;

        // Append user message.
        appendChatBubble(msg, "user");
        chatHistory.push({ role: "user", content: msg });

        input.value = "";
        updateSendState();

        // Typing indicator while waiting for the AI response.
        setSendingState(true);
        typingRow = appendTypingIndicator();

        fetch("/assistant", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ message: msg, history: chatHistory }),
        })
          .then(function (r) {
            return r.json().then(function (data) {
              return { ok: r.ok, status: r.status, data: data };
            });
          })
          .then(function (pack) {
            if (typingRow) {
              typingRow.remove();
              typingRow = null;
            }

            var reply = "";
            if (pack && pack.data && pack.data.ok && pack.data.reply) {
              reply = pack.data.reply;
            } else {
              reply =
                (pack &&
                  pack.data &&
                  (pack.data.error || pack.data.message)) ||
                "Sorry, something went wrong. Please try again.";
            }

            appendChatBubble(reply, "bot");
            chatHistory.push({ role: "assistant", content: reply });
          })
          .catch(function () {
            if (typingRow) {
              typingRow.remove();
              typingRow = null;
            }
            var errText = "Network error. Please try again.";
            appendChatBubble(errText, "bot");
            chatHistory.push({ role: "assistant", content: errText });
          })
          .finally(function () {
            setSendingState(false);
            if (input) input.focus();
          });
      });
    }

  }

  window.initAdminCharts = function () {
    var pie = document.getElementById("admin-pie-chart");
    var line = document.getElementById("admin-line-chart");
    if (typeof Chart === "undefined") return;
    var isDark =
      document.documentElement.getAttribute("data-theme") === "dark";
    var textColor = isDark ? "#e8eaed" : "#5f6368";
    var grid = isDark ? "#444746" : "#e0e0e0";

    if (pie) {
      var spam = parseInt(pie.getAttribute("data-spam"), 10) || 0;
      var safe = parseInt(pie.getAttribute("data-safe"), 10) || 0;
      if (spam === 0 && safe === 0) {
        pie.style.display = "none";
      } else {
        new Chart(pie.getContext("2d"), {
          type: "pie",
          data: {
            labels: ["Spam", "Safe"],
            datasets: [
              {
                data: [spam, safe],
                backgroundColor: ["#ea4335", "#34a853"],
                borderWidth: 2,
                borderColor: isDark ? "#2d2d2d" : "#ffffff",
                hoverOffset: 8,
              },
            ],
          },
          options: {
            responsive: true,
            animation: { duration: 900, easing: "easeOutQuart" },
            plugins: {
              legend: {
                position: "bottom",
                labels: { color: textColor, font: { family: "Roboto, sans-serif" } },
              },
            },
          },
        });
      }
    }

    if (line) {
      var labels = [];
      var s1 = [];
      var s2 = [];
      try {
        labels = JSON.parse(line.getAttribute("data-labels") || "[]");
        s1 = JSON.parse(line.getAttribute("data-spam") || "[]");
        s2 = JSON.parse(line.getAttribute("data-safe") || "[]");
      } catch (e) {
        return;
      }
      if (!labels.length) {
        line.style.display = "none";
        return;
      }
      new Chart(line.getContext("2d"), {
        type: "line",
        data: {
          labels: labels,
          datasets: [
            {
              label: "Spam",
              data: s1,
              borderColor: "#ea4335",
              tension: 0.3,
              fill: false,
            },
            {
              label: "Safe",
              data: s2,
              borderColor: "#34a853",
              tension: 0.3,
              fill: false,
            },
          ],
        },
        options: {
          responsive: true,
          animation: { duration: 900 },
          scales: {
            x: {
              ticks: { color: textColor, maxRotation: 45 },
              grid: { color: grid },
            },
            y: {
              ticks: { color: textColor },
              grid: { color: grid },
              beginAtZero: true,
            },
          },
          plugins: {
            legend: {
              labels: { color: textColor, font: { family: "Roboto, sans-serif" } },
            },
          },
        },
      });
    }
  };

  document.addEventListener("DOMContentLoaded", function () {
    initTheme();
    initRipples();
    initSidebar();
    initProfileMenu();
    initInboxPage();
    initChatWidget();

    if (document.getElementById("distribution-chart")) {
      initDashboardCounters();
      initDashboardChart();
      initUserTrendChart();
      setupUserPdfExport();
    }

    if (document.getElementById("admin-pie-chart")) {
      document.querySelectorAll(".stat-number[data-target]").forEach(function (el) {
        animateCounter(el, el.getAttribute("data-target"));
      });
      window.initAdminCharts();
      setupAdminPdfExport();
    }
  });
})();
