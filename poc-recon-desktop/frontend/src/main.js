// State variables
let currentResult = null;
let isTableExpanded = false;
let parsedBulkTargets = [];
let cachedSavedLeads = [];

document.addEventListener("DOMContentLoaded", () => {
    // 1. Setup Tab Navigation
    setupTabs();

    // 2. Setup Wails Event Listeners
    if (window.runtime && window.runtime.EventsOn) {
        window.runtime.EventsOn("recon-progress", (data) => {
            updateProgress(data.message, data.percentage);
        });

        window.runtime.EventsOn("bulk-progress", (data) => {
            updateBulkProgress(data);
        });
    }

    // 3. Setup Single Target Form
    setupSingleRecon();

    // 4. Setup Bulk CSV Discovery
    setupBulkRecon();

    // 5. Setup Saved Leads CRM
    setupSavedLeads();

    // 6. External Link Handler
    setupExternalLinks();

    // Initial cache refresh
    updateSavedLeadsCount();
});

// Tab Navigation
function setupTabs() {
    const tabButtons = document.querySelectorAll(".tab-btn");
    const tabPanels = document.querySelectorAll(".tab-panel");

    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-tab");

            tabButtons.forEach(b => b.classList.remove("active"));
            tabPanels.forEach(p => p.classList.add("hidden"));

            btn.classList.add("active");
            const targetPanel = document.getElementById(targetId);
            if (targetPanel) {
                targetPanel.classList.remove("hidden");
            }

            if (targetId === "tab-leads") {
                loadSavedLeads();
            }
        });
    });
}

// Single Reconnaissance Workflow
function setupSingleRecon() {
    const form = document.getElementById("recon-form");
    const btnStart = document.getElementById("btn-start");
    const progressCard = document.getElementById("progress-card");
    const resultsSection = document.getElementById("results-section");

    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const website = document.getElementById("input-website").value.trim();
        const name = document.getElementById("input-name").value.trim();
        const personLi = document.getElementById("input-person-li").value.trim();
        const companyLi = document.getElementById("input-company-li").value.trim();
        const proxy = document.getElementById("input-proxy").value.trim();
        const noVerify = document.getElementById("check-no-verify").checked;

        if (!website || !name || !personLi || !companyLi) {
            showToast("Please provide website, person name, person LinkedIn URL, and company LinkedIn URL.");
            return;
        }

        btnStart.disabled = true;
        progressCard.classList.remove("hidden");
        resultsSection.classList.add("hidden");
        document.getElementById("engine-status").textContent = "Scanning...";
        updateProgress("Initializing reconnaissance...", 5);

        const pattern = document.getElementById("input-pattern")?.value || "";

        try {
            if (window.go && window.go.main && window.go.main.App && window.go.main.App.RunRecon) {
                currentResult = await window.go.main.App.RunRecon({
                    website: website,
                    name: name,
                    person_linkedin: personLi,
                    company_linkedin: companyLi,
                    pattern: pattern,
                    proxy_url: proxy,
                    no_verify: noVerify
                });
                renderResults(currentResult);
                updateSavedLeadsCount();
            } else {
                setTimeout(() => {
                    const mock = createMockResult(website, name, pattern);
                    renderResults(mock);
                }, 900);
            }
        } catch (err) {
            showToast("Error: " + (err.message || err));
            updateProgress("Failed: " + err, 0);
        } finally {
            btnStart.disabled = false;
            document.getElementById("engine-status").textContent = "Engine Ready";
        }
    });

    // Toggle Permutations Table
    const btnToggleTable = document.getElementById("btn-toggle-table");
    const tableWrapper = document.getElementById("table-wrapper");
    btnToggleTable.addEventListener("click", () => {
        isTableExpanded = !isTableExpanded;
        if (isTableExpanded) {
            tableWrapper.classList.remove("hidden");
            btnToggleTable.textContent = "Hide Permutations";
        } else {
            tableWrapper.classList.add("hidden");
            btnToggleTable.textContent = "Show All Permutations";
        }
    });

    // Filter Candidates Table
    const searchInput = document.getElementById("table-search");
    searchInput.addEventListener("input", (e) => {
        const query = e.target.value.toLowerCase();
        const rows = document.querySelectorAll("#candidates-tbody tr");
        rows.forEach(row => {
            row.style.display = row.textContent.toLowerCase().includes(query) ? "" : "none";
        });
    });

    // Copy Hero Email
    document.getElementById("btn-copy-hero").addEventListener("click", () => {
        const email = document.getElementById("hero-email").textContent;
        navigator.clipboard.writeText(email).then(() => {
            showToast("Copied: " + email);
        });
    });

    // Folder & Report Actions
    const openFolder = () => {
        if (window.go && window.go.main && window.go.main.App && window.go.main.App.OpenResultsFolder) {
            window.go.main.App.OpenResultsFolder().catch(err => showToast(err));
        } else {
            showToast("Results saved in local ./results/ directory");
        }
    };

    document.getElementById("btn-results-folder").addEventListener("click", openFolder);
    document.getElementById("btn-open-folder-action").addEventListener("click", openFolder);

    document.getElementById("btn-open-report-web").addEventListener("click", () => {
        if (!currentResult) return;
        if (window.go && window.go.main && window.go.main.App && window.go.main.App.OpenHTMLReport) {
            window.go.main.App.OpenHTMLReport(currentResult.target_domain, currentResult.person.first_name).catch(err => showToast(err));
        } else {
            showToast("Opening browser report...");
        }
    });
}

// Bulk CSV Batch Discovery Workflow
function setupBulkRecon() {
    const dropzone = document.getElementById("bulk-dropzone");
    const fileInput = document.getElementById("bulk-file-input");
    const pasteArea = document.getElementById("bulk-paste-text");
    const btnStartBulk = document.getElementById("btn-start-bulk");
    const progressCard = document.getElementById("bulk-progress-card");
    const resultsSection = document.getElementById("bulk-results-section");

    // Dropzone Click
    dropzone.addEventListener("click", () => fileInput.click());

    // File Input change
    fileInput.addEventListener("change", (e) => {
        if (e.target.files && e.target.files[0]) {
            handleCSVFile(e.target.files[0]);
        }
    });

    // Drag & Drop
    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropzone.classList.add("drag-over");
    });
    dropzone.addEventListener("dragleave", () => {
        dropzone.classList.remove("drag-over");
    });
    dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropzone.classList.remove("drag-over");
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            handleCSVFile(e.dataTransfer.files[0]);
        }
    });

    // Textarea input
    pasteArea.addEventListener("input", () => {
        const text = pasteArea.value.trim();
        if (text) {
            parseCSVText(text);
        } else {
            parsedBulkTargets = [];
            btnStartBulk.disabled = true;
            btnStartBulk.querySelector("span").textContent = "🚀 Start Batch Discovery";
        }
    });

    function handleCSVFile(file) {
        const reader = new FileReader();
        reader.onload = (event) => {
            const content = event.target.result;
            pasteArea.value = content;
            parseCSVText(content);
        };
        reader.readAsText(file);
    }

    async function parseCSVText(content) {
        try {
            if (window.go && window.go.main && window.go.main.App && window.go.main.App.ParseCSVContent) {
                const targets = await window.go.main.App.ParseCSVContent(content);
                parsedBulkTargets = targets || [];
            } else {
                // Client-side fallback preview
                parsedBulkTargets = parseSimpleCSVFallback(content);
            }

            if (parsedBulkTargets.length > 0) {
                btnStartBulk.disabled = false;
                btnStartBulk.querySelector("span").textContent = `🚀 Start Batch Discovery (${parsedBulkTargets.length} Prospects)`;
                showToast(`Loaded ${parsedBulkTargets.length} targets ready for scan`);
            } else {
                btnStartBulk.disabled = true;
                btnStartBulk.querySelector("span").textContent = "🚀 Start Batch Discovery";
            }
        } catch (err) {
            showToast("Failed to parse CSV: " + (err.message || err));
            btnStartBulk.disabled = true;
        }
    }

    // Start Batch Scan
    btnStartBulk.addEventListener("click", async () => {
        if (parsedBulkTargets.length === 0) return;

        btnStartBulk.disabled = true;
        progressCard.classList.remove("hidden");
        resultsSection.classList.add("hidden");

        const noVerify = document.getElementById("bulk-check-no-verify").checked;
        const proxy = document.getElementById("input-proxy")?.value.trim() || "";

        // Reset Counters
        document.getElementById("stat-processed").textContent = "0";
        document.getElementById("stat-valid").textContent = "0";
        document.getElementById("stat-heuristics").textContent = "0";

        try {
            if (window.go && window.go.main && window.go.main.App && window.go.main.App.RunBulkRecon) {
                const results = await window.go.main.App.RunBulkRecon(parsedBulkTargets, proxy, noVerify);
                renderBulkResults(results);
                updateSavedLeadsCount();
            } else {
                showToast("Simulating mock batch discovery...");
                setTimeout(() => {
                    const mockResults = parsedBulkTargets.map(t => ({
                        full_name: t.full_name,
                        domain: t.domain,
                        email: (t.full_name.replace(" ", ".").toLowerCase()) + "@" + t.domain,
                        confidence: 90,
                        status: "VALID",
                        pattern: "first.last",
                        mail_provider: "Google Workspace",
                        verified_at: new Date().toLocaleTimeString()
                    }));
                    renderBulkResults(mockResults);
                }, 1200);
            }
        } catch (err) {
            showToast("Bulk scan error: " + (err.message || err));
        } finally {
            btnStartBulk.disabled = false;
            progressCard.classList.add("hidden");
        }
    });

    // Export Bulk CSV
    document.getElementById("btn-export-bulk-csv").addEventListener("click", () => {
        if (window.go && window.go.main && window.go.main.App && window.go.main.App.OpenResultsFolder) {
            window.go.main.App.OpenResultsFolder().catch(err => showToast(err));
            showToast("Enriched CSV saved in results/bulk_verified_leads.csv");
        }
    });

    document.getElementById("btn-open-bulk-folder").addEventListener("click", () => {
        if (window.go && window.go.main && window.go.main.App && window.go.main.App.OpenResultsFolder) {
            window.go.main.App.OpenResultsFolder();
        }
    });
}

function updateBulkProgress(data) {
    const fillEl = document.getElementById("bulk-progress-bar-fill");
    const pctEl = document.getElementById("bulk-progress-percentage");
    const msgEl = document.getElementById("bulk-progress-message");

    if (fillEl) fillEl.style.width = data.percentage + "%";
    if (pctEl) pctEl.textContent = data.percentage + "%";
    if (msgEl) {
        msgEl.textContent = `Analyzing ${data.index}/${data.total}: ${data.current_lead.full_name} (${data.current_lead.domain})`;
    }

    document.getElementById("stat-processed").textContent = data.index;
    document.getElementById("stat-valid").textContent = data.valid_count;
    document.getElementById("stat-heuristics").textContent = Math.max(0, data.index - data.valid_count);
}

function renderBulkResults(results) {
    const resultsSection = document.getElementById("bulk-results-section");
    const tbody = document.getElementById("bulk-results-tbody");
    tbody.innerHTML = "";

    resultsSection.classList.remove("hidden");
    document.getElementById("bulk-total-count").textContent = results.length;

    results.forEach((r, idx) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><strong>${escapeHtml(r.full_name)}</strong></td>
            <td><code>${escapeHtml(r.domain)}</code></td>
            <td><strong style="color: #38bdf8;">${escapeHtml(r.email)}</strong></td>
            <td><span style="color: var(--accent-sky); font-weight: 700;">${r.confidence || 0}%</span></td>
            <td><span class="badge ${getBadgeClass(r.status)}">${escapeHtml(r.status)}</span></td>
            <td><code>${escapeHtml(r.pattern || "-")}</code></td>
            <td>
                <button class="btn-text btn-copy-row" data-email="${escapeHtml(r.email)}" style="font-size: 0.8rem; padding: 2px 8px;">
                    📋 Copy
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });

    tbody.querySelectorAll(".btn-copy-row").forEach(btn => {
        btn.addEventListener("click", () => {
            const em = btn.getAttribute("data-email");
            navigator.clipboard.writeText(em).then(() => showToast("Copied: " + em));
        });
    });
}

// Saved Leads CRM Workflow
function setupSavedLeads() {
    const searchInput = document.getElementById("leads-search-input");
    searchInput.addEventListener("input", (e) => {
        const q = e.target.value.toLowerCase();
        const filtered = cachedSavedLeads.filter(l =>
            l.full_name.toLowerCase().includes(q) ||
            l.domain.toLowerCase().includes(q) ||
            l.email.toLowerCase().includes(q)
        );
        renderSavedLeadsTable(filtered);
    });

    document.getElementById("btn-export-all-leads").addEventListener("click", async () => {
        try {
            if (window.go && window.go.main && window.go.main.App && window.go.main.App.ExportSavedLeadsCSV) {
                const path = await window.go.main.App.ExportSavedLeadsCSV();
                showToast("All leads exported to: " + path);
                if (window.go.main.App.OpenResultsFolder) {
                    window.go.main.App.OpenResultsFolder();
                }
            } else {
                showToast("Leads exported to results/saved_leads_export.csv");
            }
        } catch (err) {
            showToast("Export error: " + err);
        }
    });

    document.getElementById("btn-clear-leads").addEventListener("click", async () => {
        if (!confirm("Are you sure you want to clear all saved leads from history?")) return;
        try {
            if (window.go && window.go.main && window.go.main.App && window.go.main.App.ClearSavedLeads) {
                await window.go.main.App.ClearSavedLeads();
            }
            cachedSavedLeads = [];
            renderSavedLeadsTable([]);
            updateSavedLeadsCount();
            showToast("History cleared");
        } catch (err) {
            showToast("Clear error: " + err);
        }
    });
}

async function loadSavedLeads() {
    try {
        if (window.go && window.go.main && window.go.main.App && window.go.main.App.GetSavedLeads) {
            cachedSavedLeads = await window.go.main.App.GetSavedLeads() || [];
        } else {
            cachedSavedLeads = [];
        }
        renderSavedLeadsTable(cachedSavedLeads);
        updateSavedLeadsCount();
    } catch (err) {
        console.error(err);
    }
}

function renderSavedLeadsTable(leads) {
    const tbody = document.getElementById("saved-leads-tbody");
    tbody.innerHTML = "";

    if (leads.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 2rem;">No saved leads found. Run a Single or Batch investigation to automatically build your list.</td></tr>`;
        return;
    }

    leads.forEach((l) => {
        const tr = document.createElement("tr");
        const dateStr = l.verified_at ? new Date(l.verified_at).toLocaleDateString() : "-";
        tr.innerHTML = `
            <td><strong>${escapeHtml(l.full_name)}</strong></td>
            <td><code>${escapeHtml(l.domain)}</code></td>
            <td><strong style="color: #38bdf8;">${escapeHtml(l.email)}</strong></td>
            <td><span style="color: var(--accent-sky); font-weight: 700;">${l.confidence || 0}%</span></td>
            <td><span class="badge ${getBadgeClass(l.status)}">${escapeHtml(l.status)}</span></td>
            <td>${escapeHtml(l.provider || "Standard")}</td>
            <td><small style="color: var(--text-muted);">${dateStr}</small></td>
            <td>
                <button class="btn-text btn-copy-lead" data-email="${escapeHtml(l.email)}" style="font-size: 0.8rem; padding: 2px 8px;">
                    📋 Copy
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });

    tbody.querySelectorAll(".btn-copy-lead").forEach(btn => {
        btn.addEventListener("click", () => {
            const em = btn.getAttribute("data-email");
            navigator.clipboard.writeText(em).then(() => showToast("Copied: " + em));
        });
    });
}

async function updateSavedLeadsCount() {
    try {
        let count = 0;
        if (window.go && window.go.main && window.go.main.App && window.go.main.App.GetSavedLeads) {
            const leads = await window.go.main.App.GetSavedLeads();
            count = leads ? leads.length : 0;
        }
        const pill = document.getElementById("saved-count-pill");
        if (pill) pill.textContent = count;
    } catch (e) {
        console.error(e);
    }
}

// Single Recon Result Rendering
function renderResults(result) {
    currentResult = result;
    const progressCard = document.getElementById("progress-card");
    const resultsSection = document.getElementById("results-section");

    progressCard.classList.add("hidden");
    resultsSection.classList.remove("hidden");

    // Profile card
    const first = result.person.first_name || "Jane";
    const last = result.person.last_name || "Doe";
    document.getElementById("target-initials").textContent = (first[0] + (last[0] || "")).toUpperCase();
    document.getElementById("target-name").textContent = result.person.full_name;
    document.getElementById("target-domain").textContent = result.target_domain;
    document.getElementById("target-provider").textContent = result.provider ? result.provider.name : "Standard Mail";
    document.getElementById("target-pattern").textContent = "Pattern: " + (result.detected_pattern || "Corporate Standard");

    const p25Pill = document.getElementById("pill-port25");
    p25Pill.textContent = result.port_25_open ? "Port 25 Open" : "Port 25 Closed (ISP)";
    p25Pill.className = result.port_25_open ? "badge badge-success" : "badge badge-info";

    const caPill = document.getElementById("pill-catchall");
    caPill.textContent = result.is_catch_all ? "Catch-All Active" : "No Catch-All";
    caPill.className = result.is_catch_all ? "badge badge-warning" : "badge badge-info";

    // Hero card
    const best = result.best_candidate || (result.candidates && result.candidates[0]);
    if (best) {
        document.getElementById("hero-email").textContent = best.email;
        document.getElementById("hero-confidence").textContent = best.confidence || 95;
        document.getElementById("hero-status-label").textContent = best.status;
        document.getElementById("hero-explanation").textContent = best.smtp_message || "Verified corporate address.";
    }

    // Permutations Table
    const tbody = document.getElementById("candidates-tbody");
    tbody.innerHTML = "";
    document.getElementById("total-count").textContent = result.candidates ? result.candidates.length : 0;

    if (result.candidates) {
        result.candidates.forEach((c) => {
            const tr = document.createElement("tr");
            const codeStr = c.smtp_code ? String(c.smtp_code) : "-";
            tr.innerHTML = `
                <td><strong style="color: #fff;">${escapeHtml(c.email)}</strong></td>
                <td><code>${escapeHtml(c.pattern_name)}</code></td>
                <td><span style="color: var(--accent-sky); font-weight: 700;">${c.confidence || 0}%</span></td>
                <td><span class="badge ${getBadgeClass(c.status)}">${escapeHtml(c.status)}</span></td>
                <td>${codeStr}</td>
                <td><small style="color: var(--text-muted);">${escapeHtml(c.smtp_message || "")}</small></td>
            `;
            tbody.appendChild(tr);
        });
    }

    const baseName = `results/${result.target_domain}_${result.person.first_name.toLowerCase()}`;
    document.getElementById("export-paths").textContent = `${baseName}_report.html`;
}

// External Links Interceptor
function setupExternalLinks() {
    document.addEventListener("click", (e) => {
        const link = e.target.closest("a[href^='http']");
        if (link) {
            e.preventDefault();
            const url = link.getAttribute("href");
            if (window.runtime && window.runtime.BrowserOpenURL) {
                window.runtime.BrowserOpenURL(url);
            } else if (window.go && window.go.main && window.go.main.App && window.go.main.App.OpenURL) {
                window.go.main.App.OpenURL(url).catch(err => console.error(err));
            } else {
                window.open(url, "_blank");
            }
        }
    });
}

function updateProgress(message, pct) {
    const msgEl = document.getElementById("progress-message");
    const pctEl = document.getElementById("progress-percentage");
    const fillEl = document.getElementById("progress-bar-fill");

    if (msgEl) msgEl.textContent = message;
    if (pctEl) pctEl.textContent = pct + "%";
    if (fillEl) fillEl.style.width = pct + "%";
}

function getBadgeClass(status) {
    const s = String(status).toUpperCase();
    if (s.includes("VALID") && !s.includes("UNVERIFIED")) return "badge-success";
    if (s.includes("INVALID") || s.includes("REJECTED")) return "badge-danger";
    return "badge-info";
}

function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function showToast(message) {
    const toast = document.getElementById("toast");
    toast.textContent = message;
    toast.classList.remove("hidden");
    setTimeout(() => {
        toast.classList.add("hidden");
    }, 2500);
}

function parseSimpleCSVFallback(content) {
    const lines = content.split(/\r?\n/).filter(l => l.trim() !== "");
    if (lines.length < 2) return [];

    const list = [];
    for (let i = 1; i < lines.length; i++) {
        const parts = lines[i].split(",").map(p => p.trim());
        if (parts.length >= 2) {
            list.push({
                full_name: parts[0],
                domain: parts[1].replace(/https?:\/\//, "").replace(/\/.*$/, "")
            });
        }
    }
    return list;
}

function createMockResult(domain, name, preferredPattern) {
    const fn = (name.split(" ")[0] || "user").toLowerCase();
    const ln = (name.split(" ")[1] || "name").toLowerCase();
    const pat = preferredPattern || "first.last";

    let email = `${fn}.${ln}@${domain}`;
    return {
        target_domain: domain,
        person: { full_name: name, first_name: name.split(" ")[0], last_name: name.split(" ")[1] || "" },
        mx_records: [{ host: "aspmx.l.google.com", priority: 1 }],
        provider: { name: "Google Workspace" },
        port_25_open: false,
        is_catch_all: false,
        best_candidate: {
            email: email,
            pattern_name: pat,
            confidence: 95,
            status: "VALID",
            smtp_message: "OSINT verified corporate domain pattern match."
        },
        candidates: [
            { email: email, pattern_name: pat, confidence: 95, status: "VALID", smtp_message: "Top candidate pattern" },
            { email: `${fn}@${domain}`, pattern_name: "first", confidence: 60, status: "UNVERIFIED", smtp_message: "Alternative pattern" }
        ]
    };
}
