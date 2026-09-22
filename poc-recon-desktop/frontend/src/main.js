// State variables
let currentResult = null;
let isTableExpanded = true;
let parsedBulkTargets = [];
let cachedSavedLeads = [];
let builderRows = [];

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

    // 4. Setup Bulk Lead Discovery & Prospect Builder
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

        if (!website || !name) {
            showToast("Please provide target website domain and person name.");
            return;
        }

        btnStart.disabled = true;
        progressCard.classList.remove("hidden");
        resultsSection.classList.add("hidden");
        document.getElementById("engine-status").textContent = "Scanning...";
        updateProgress("Initializing reconnaissance & OSINT queries...", 5);

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

// Bulk Lead Discovery & Interactive Prospect Builder
function setupBulkRecon() {
    const btnModeBuilder = document.getElementById("btn-mode-builder");
    const btnModeFile = document.getElementById("btn-mode-file");
    const builderContainer = document.getElementById("bulk-builder-container");
    const fileContainer = document.getElementById("bulk-file-container");

    const btnAddRow = document.getElementById("btn-add-prospect-row");
    const btnLoadSamples = document.getElementById("btn-load-sample-prospects");
    const btnClearRows = document.getElementById("btn-clear-prospect-rows");
    const btnDownloadCSV = document.getElementById("btn-download-builder-csv");
    const btnStartBuilder = document.getElementById("btn-start-builder-discovery");

    const dropzone = document.getElementById("bulk-dropzone");
    const fileInput = document.getElementById("bulk-file-input");
    const pasteArea = document.getElementById("bulk-paste-text");
    const btnStartBulk = document.getElementById("btn-start-bulk");

    const progressCard = document.getElementById("bulk-progress-card");
    const resultsSection = document.getElementById("bulk-results-section");

    // Mode Switcher
    btnModeBuilder.addEventListener("click", () => {
        btnModeBuilder.classList.add("active");
        btnModeFile.classList.remove("active");
        builderContainer.classList.remove("hidden");
        fileContainer.classList.add("hidden");
    });

    btnModeFile.addEventListener("click", () => {
        btnModeFile.classList.add("active");
        btnModeBuilder.classList.remove("active");
        fileContainer.classList.remove("hidden");
        builderContainer.classList.add("hidden");
    });

    // Initialize Builder Rows
    builderRows = [
        { id: 1, firstName: "", lastName: "", domain: "", personLi: "", companyLi: "" },
        { id: 2, firstName: "", lastName: "", domain: "", personLi: "", companyLi: "" },
        { id: 3, firstName: "", lastName: "", domain: "", personLi: "", companyLi: "" }
    ];
    renderBuilderTable();

    btnAddRow.addEventListener("click", () => {
        addBuilderRow();
    });

    btnLoadSamples.addEventListener("click", () => {
        loadSampleLeads();
    });

    btnClearRows.addEventListener("click", () => {
        builderRows = [
            { id: 1, firstName: "", lastName: "", domain: "", personLi: "", companyLi: "" }
        ];
        renderBuilderTable();
        showToast("Cleared all prospect rows");
    });

    btnDownloadCSV.addEventListener("click", () => {
        downloadGeneratedCSV();
    });

    btnStartBuilder.addEventListener("click", async () => {
        const validTargets = getValidBuilderTargets();
        if (validTargets.length === 0) {
            showToast("Please fill in at least one prospect with First Name and Domain.");
            return;
        }

        const noVerify = document.getElementById("bulk-builder-no-verify").checked;
        const proxy = document.getElementById("input-proxy")?.value.trim() || "";
        await executeBatchScan(validTargets, proxy, noVerify);
    });

    // File Input & Drag and Drop for CSV
    dropzone.addEventListener("click", () => fileInput.click());

    fileInput.addEventListener("change", (e) => {
        if (e.target.files && e.target.files[0]) {
            handleCSVFile(e.target.files[0]);
        }
    });

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

    btnStartBulk.addEventListener("click", async () => {
        if (parsedBulkTargets.length === 0) return;
        const noVerify = document.getElementById("bulk-check-no-verify").checked;
        const proxy = document.getElementById("input-proxy")?.value.trim() || "";
        await executeBatchScan(parsedBulkTargets, proxy, noVerify);
    });

    // Execute Batch Scan Common Helper
    async function executeBatchScan(targets, proxy, noVerify) {
        btnStartBulk.disabled = true;
        btnStartBuilder.disabled = true;
        progressCard.classList.remove("hidden");
        resultsSection.classList.add("hidden");

        document.getElementById("stat-processed").textContent = "0";
        document.getElementById("stat-valid").textContent = "0";
        document.getElementById("stat-heuristics").textContent = "0";

        try {
            if (window.go && window.go.main && window.go.main.App && window.go.main.App.RunBulkRecon) {
                const results = await window.go.main.App.RunBulkRecon(targets, proxy, noVerify);
                renderBulkResults(results);
                updateSavedLeadsCount();
            } else {
                showToast("Simulating multi-pattern batch discovery...");
                setTimeout(() => {
                    const mockResults = targets.map(t => {
                        const fn = (t.first_name || (t.full_name ? t.full_name.split(" ")[0] : "john")).toLowerCase();
                        const ln = (t.last_name || (t.full_name && t.full_name.split(" ")[1] ? t.full_name.split(" ")[1] : "doe")).toLowerCase();
                        const dom = (t.domain || "example.com").toLowerCase().replace(/https?:\/\//, "").replace(/\/.*$/, "");
                        const fInit = fn ? fn[0] : "j";

                        const allPatterns = [
                            `${fn}.${ln}@${dom}`,
                            `${fn}@${dom}`,
                            `${fInit}${ln}@${dom}`,
                            `${fn}${ln}@${dom}`,
                            `${fInit}.${ln}@${dom}`
                        ];

                        return {
                            full_name: t.full_name || `${fn} ${ln}`,
                            first_name: fn,
                            last_name: ln,
                            domain: dom,
                            email: allPatterns[0],
                            confidence: 90,
                            status: "VALID",
                            pattern: "first.last",
                            mail_provider: "Google Workspace",
                            verified_at: new Date().toLocaleTimeString(),
                            alternatives: allPatterns.slice(1),
                            alternative_emails: allPatterns.slice(1).join("; ")
                        };
                    });
                    renderBulkResults(mockResults);
                }, 1200);
            }
        } catch (err) {
            showToast("Bulk scan error: " + (err.message || err));
        } finally {
            btnStartBulk.disabled = false;
            btnStartBuilder.disabled = false;
            progressCard.classList.add("hidden");
        }
    }

    // Export Bulk CSV
    document.getElementById("btn-export-bulk-csv").addEventListener("click", () => {
        if (window.go && window.go.main && window.go.main.App && window.go.main.App.OpenResultsFolder) {
            window.go.main.App.OpenResultsFolder().catch(err => showToast(err));
            showToast("Enriched CSV saved in results/bulk_verified_leads.csv");
        } else {
            showToast("Enriched CSV saved in results/bulk_verified_leads.csv");
        }
    });

    document.getElementById("btn-open-bulk-folder").addEventListener("click", () => {
        if (window.go && window.go.main && window.go.main.App && window.go.main.App.OpenResultsFolder) {
            window.go.main.App.OpenResultsFolder();
        }
    });
}

// Prospect Builder Table Logic
function renderBuilderTable() {
    const tbody = document.getElementById("builder-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    builderRows.forEach((row, idx) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td class="builder-row-num">${idx + 1}</td>
            <td>
                <input type="text" class="builder-input row-first" placeholder="e.g. Satya" value="${escapeHtml(row.firstName)}" data-id="${row.id}">
            </td>
            <td>
                <input type="text" class="builder-input row-last" placeholder="e.g. Nadella" value="${escapeHtml(row.lastName)}" data-id="${row.id}">
            </td>
            <td>
                <input type="text" class="builder-input row-domain" placeholder="e.g. microsoft.com" value="${escapeHtml(row.domain)}" data-id="${row.id}">
            </td>
            <td>
                <input type="text" class="builder-input row-person-li" placeholder="https://linkedin.com/in/..." value="${escapeHtml(row.personLi)}" data-id="${row.id}">
            </td>
            <td>
                <input type="text" class="builder-input row-company-li" placeholder="https://linkedin.com/company/..." value="${escapeHtml(row.companyLi)}" data-id="${row.id}">
            </td>
            <td style="text-align: center;">
                <button type="button" class="btn-remove-row" data-id="${row.id}" title="Remove row">✕</button>
            </td>
        `;
        tbody.appendChild(tr);
    });

    // Update Counter
    updateBuilderCounter();

    // Attach Event Handlers
    tbody.querySelectorAll("input").forEach(input => {
        input.addEventListener("input", (e) => {
            const id = parseInt(e.target.getAttribute("data-id"));
            const r = builderRows.find(item => item.id === id);
            if (!r) return;

            if (e.target.classList.contains("row-first")) r.firstName = e.target.value.trim();
            if (e.target.classList.contains("row-last")) r.lastName = e.target.value.trim();
            if (e.target.classList.contains("row-domain")) r.domain = e.target.value.trim();
            if (e.target.classList.contains("row-person-li")) r.personLi = e.target.value.trim();
            if (e.target.classList.contains("row-company-li")) r.companyLi = e.target.value.trim();

            updateBuilderCounter();
        });

        // Hit Enter on last field to add a new row
        input.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                addBuilderRow();
            }
        });
    });

    tbody.querySelectorAll(".btn-remove-row").forEach(btn => {
        btn.addEventListener("click", () => {
            const id = parseInt(btn.getAttribute("data-id"));
            if (builderRows.length <= 1) {
                builderRows = [{ id: 1, firstName: "", lastName: "", domain: "", personLi: "", companyLi: "" }];
            } else {
                builderRows = builderRows.filter(r => r.id !== id);
            }
            renderBuilderTable();
        });
    });
}

function addBuilderRow() {
    const nextId = builderRows.length > 0 ? Math.max(...builderRows.map(r => r.id)) + 1 : 1;
    builderRows.push({ id: nextId, firstName: "", lastName: "", domain: "", personLi: "", companyLi: "" });
    renderBuilderTable();

    // Focus first input of the newly added row
    const tbody = document.getElementById("builder-tbody");
    const lastRow = tbody.lastElementChild;
    if (lastRow) {
        const firstInput = lastRow.querySelector(".row-first");
        if (firstInput) firstInput.focus();
    }
}

function updateBuilderCounter() {
    const countEl = document.getElementById("builder-row-count");
    if (!countEl) return;
    const valid = builderRows.filter(r => r.firstName && r.domain).length;
    countEl.textContent = `${valid} Prospect${valid === 1 ? "" : "s"} Ready`;
    countEl.className = valid > 0 ? "badge badge-success" : "badge badge-info";
}

function loadSampleLeads() {
    builderRows = [
        { id: 1, firstName: "Satya", lastName: "Nadella", domain: "microsoft.com", personLi: "https://www.linkedin.com/in/satyanadella", companyLi: "https://www.linkedin.com/company/microsoft" },
        { id: 2, firstName: "Tim", lastName: "Cook", domain: "apple.com", personLi: "https://www.linkedin.com/in/tim-cook", companyLi: "https://www.linkedin.com/company/apple" },
        { id: 3, firstName: "Sam", lastName: "Altman", domain: "openai.com", personLi: "https://www.linkedin.com/in/samaltman", companyLi: "https://www.linkedin.com/company/openai" }
    ];
    renderBuilderTable();
    showToast("Loaded 3 corporate sample leads ready for discovery!");
}

function getValidBuilderTargets() {
    const targets = [];
    builderRows.forEach(r => {
        const fn = r.firstName.trim();
        const ln = r.lastName.trim();
        const dom = r.domain.trim().replace(/https?:\/\//, "").replace(/\/.*$/, "");
        if (fn && dom) {
            targets.push({
                domain: dom,
                full_name: ln ? `${fn} ${ln}` : fn,
                first_name: fn,
                last_name: ln,
                person_linkedin: r.personLi.trim(),
                company_linkedin: r.companyLi.trim()
            });
        }
    });
    return targets;
}

function downloadGeneratedCSV() {
    const valid = getValidBuilderTargets();
    if (valid.length === 0) {
        showToast("Please enter at least one prospect with First Name and Domain to export.");
        return;
    }

    const header = "First Name,Last Name,Company Domain,Person LinkedIn,Company LinkedIn\n";
    const rows = valid.map(t => 
        `"${t.first_name}","${t.last_name}","${t.domain}","${t.person_linkedin}","${t.company_linkedin}"`
    ).join("\n");
    const csvContent = header + rows;

    // Trigger local backend save if available
    if (window.go && window.go.main && window.go.main.App && window.go.main.App.SaveGeneratedCSV) {
        window.go.main.App.SaveGeneratedCSV(csvContent).then(path => {
            showToast(`Auto-generated CSV saved to: ${path}`);
        }).catch(err => console.error(err));
    }

    // Trigger browser file download
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `prospects_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast(`Exported ${valid.length} prospects to CSV`);
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

    results.forEach((r) => {
        const tr = document.createElement("tr");

        // Format Alternative Permutations
        const alts = r.alternatives || [];
        let altsHtml = `<span style="color: var(--text-muted); font-size: 0.8rem;">-</span>`;
        if (alts.length > 0) {
            const badges = alts.map(a => 
                `<span class="batch-alt-badge btn-copy-alt" data-email="${escapeHtml(a)}" title="Click to copy ${escapeHtml(a)}">${escapeHtml(a)}</span>`
            ).join("");
            altsHtml = `<div class="batch-alts-tags">${badges}</div>`;
        }

        tr.innerHTML = `
            <td><strong>${escapeHtml(r.full_name)}</strong></td>
            <td><code>${escapeHtml(r.domain)}</code></td>
            <td><strong style="color: #38bdf8;">${escapeHtml(r.email)}</strong></td>
            <td><span style="color: var(--accent-sky); font-weight: 700;">${r.confidence || 0}%</span></td>
            <td><span class="badge ${getBadgeClass(r.status)}">${escapeHtml(r.status)}</span></td>
            <td><code>${escapeHtml(r.pattern || "-")}</code></td>
            <td class="batch-alts-cell">${altsHtml}</td>
            <td>
                <div style="display: flex; gap: 4px;">
                    <button class="btn-text btn-copy-row" data-email="${escapeHtml(r.email)}" style="font-size: 0.78rem; padding: 2px 6px;" title="Copy primary verified email">
                        📋 Copy
                    </button>
                    ${alts.length > 0 ? `
                    <button class="btn-text btn-copy-all-row" data-all="${escapeHtml([r.email, ...alts].join(','))}" style="font-size: 0.78rem; padding: 2px 6px;" title="Copy all candidate emails">
                        📑 All
                    </button>` : ""}
                </div>
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

    tbody.querySelectorAll(".btn-copy-alt").forEach(badge => {
        badge.addEventListener("click", () => {
            const em = badge.getAttribute("data-email");
            navigator.clipboard.writeText(em).then(() => showToast("Copied: " + em));
        });
    });

    tbody.querySelectorAll(".btn-copy-all-row").forEach(btn => {
        btn.addEventListener("click", () => {
            const all = btn.getAttribute("data-all").replace(/,/g, "\n");
            navigator.clipboard.writeText(all).then(() => showToast("Copied all permutations for lead"));
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
    p25Pill.textContent = result.port_25_open ? "Port 25 Open" : "Port 25 Filtered (ISP)";
    p25Pill.className = result.port_25_open ? "badge badge-success" : "badge badge-info";

    const caPill = document.getElementById("pill-catchall");
    caPill.textContent = result.is_catch_all ? "Catch-All Active" : "No Catch-All";
    caPill.className = result.is_catch_all ? "badge badge-warning" : "badge badge-info";

    // Hero card
    const best = result.best_candidate || (result.candidates && result.candidates[0]);
    if (best) {
        document.getElementById("hero-email").textContent = best.email;
        document.getElementById("hero-confidence").textContent = best.confidence || 85;
        document.getElementById("hero-status-label").textContent = best.status;
        document.getElementById("hero-explanation").textContent = best.smtp_message || "Target corporate email candidate.";
    }

    // Render Alternative Permutations Pills in Hero Card
    const altsContainer = document.getElementById("hero-alternatives-container");
    const altsPills = document.getElementById("hero-alternatives-pills");
    if (altsPills) {
        altsPills.innerHTML = "";
        const candidates = result.candidates || [];
        const bestEmail = best ? best.email : "";
        const alternatives = candidates.filter(c => c.email && c.email.toLowerCase() !== bestEmail.toLowerCase());

        if (alternatives.length > 0) {
            if (altsContainer) altsContainer.classList.remove("hidden");
            alternatives.forEach(alt => {
                const pill = document.createElement("button");
                pill.type = "button";
                pill.className = "alt-pill";
                pill.title = `Click to copy ${alt.email} (${alt.pattern_name})`;
                pill.innerHTML = `
                    <span>${escapeHtml(alt.email)}</span>
                    <span class="alt-pill-pattern">${escapeHtml(alt.pattern_name)}</span>
                `;
                pill.addEventListener("click", () => {
                    navigator.clipboard.writeText(alt.email).then(() => {
                        showToast("Copied: " + alt.email);
                    });
                });
                altsPills.appendChild(pill);
            });

            const btnCopyAll = document.getElementById("btn-copy-all-alts");
            if (btnCopyAll) {
                btnCopyAll.onclick = () => {
                    const allEmails = [bestEmail, ...alternatives.map(a => a.email)].filter(Boolean).join("\n");
                    navigator.clipboard.writeText(allEmails).then(() => {
                        showToast(`Copied all ${alternatives.length + 1} email permutations`);
                    });
                };
            }
        } else if (altsContainer) {
            altsContainer.classList.add("hidden");
        }
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
        const parts = lines[i].split(",").map(p => p.trim().replace(/^["']|["']$/g, ""));
        if (parts.length >= 2) {
            const rawName = parts[0] || "";
            const fn = rawName.split(" ")[0] || "";
            const ln = rawName.split(" ")[1] || "";
            list.push({
                full_name: rawName,
                first_name: fn,
                last_name: ln,
                domain: parts[1].replace(/https?:\/\//, "").replace(/\/.*$/, "")
            });
        }
    }
    return list;
}

// Generate Realistic Multi-Pattern Permutations
function generatePermutationsList(domain, firstName, lastName, preferredPattern) {
    const fn = (firstName || "user").toLowerCase().replace(/[^a-z0-9]/g, "");
    const ln = (lastName || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    const fInit = fn ? fn[0] : "u";
    const lInit = ln ? ln[0] : "";
    const dom = domain.toLowerCase().replace(/https?:\/\//, "").replace(/\/.*$/, "").trim();

    const raw = [];
    if (ln) {
        raw.push(
            { pattern: "first.last", email: `${fn}.${ln}@${dom}` },
            { pattern: "first", email: `${fn}@${dom}` },
            { pattern: "flast", email: `${fInit}${ln}@${dom}` },
            { pattern: "firstlast", email: `${fn}${ln}@${dom}` },
            { pattern: "first_last", email: `${fn}_${ln}@${dom}` },
            { pattern: "last.first", email: `${ln}.${fn}@${dom}` },
            { pattern: "f.last", email: `${fInit}.${ln}@${dom}` },
            { pattern: "last", email: `${ln}@${dom}` },
            { pattern: "first.l", email: `${fn}.${lInit}@${dom}` },
            { pattern: "lfirst", email: `${lInit}${fn}@${dom}` }
        );
    } else {
        raw.push(
            { pattern: "first", email: `${fn}@${dom}` },
            { pattern: "contact", email: `contact@${dom}` },
            { pattern: "info", email: `info@${dom}` }
        );
    }

    const activePat = (preferredPattern || "").toLowerCase().trim();
    if (activePat) {
        raw.sort((a, b) => (a.pattern === activePat ? -1 : b.pattern === activePat ? 1 : 0));
    }

    return raw.map((r, idx) => {
        let conf = 75 - idx * 5;
        if (r.pattern === activePat) conf = 90;
        return {
            email: r.email,
            pattern_name: r.pattern,
            confidence: conf > 30 ? conf : 30,
            status: idx === 0 && activePat ? "VALID" : "UNVERIFIED",
            smtp_message: idx === 0 && activePat ? "Matched confirmed naming pattern" : "Candidate corporate variation"
        };
    });
}

function createMockResult(domain, name, preferredPattern) {
    const fn = (name.split(" ")[0] || "user");
    const ln = (name.split(" ")[1] || "name");
    const candidates = generatePermutationsList(domain, fn, ln, preferredPattern);
    const best = candidates[0];

    return {
        target_domain: domain,
        person: { full_name: name, first_name: fn, last_name: ln },
        mx_records: [{ host: "aspmx.l.google.com", priority: 1 }],
        provider: { name: "Google Workspace" },
        port_25_open: false,
        is_catch_all: false,
        detected_pattern: preferredPattern || "Corporate Standard",
        best_candidate: best,
        candidates: candidates
    };
}
