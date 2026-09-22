// State variables
let currentResult = null;
let isTableExpanded = false;

document.addEventListener("DOMContentLoaded", () => {
    // Check Wails runtime
    if (window.runtime && window.runtime.EventsOn) {
        window.runtime.EventsOn("recon-progress", (data) => {
            updateProgress(data.message, data.percentage);
        });
    }

    const form = document.getElementById("recon-form");
    const btnStart = document.getElementById("btn-start");
    const progressCard = document.getElementById("progress-card");
    const resultsSection = document.getElementById("results-section");

    // Form Submit
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

        // Reset & show progress
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
            } else {
                // Mock test mode if running inside standard browser outside Wails
                console.warn("Wails runtime not detected, simulating mock data for UI testing...");
                setTimeout(() => {
                    updateProgress("Probing DNS...", 50);
                    setTimeout(() => {
                        const mock = createMockResult(website, name, pattern);
                        renderResults(mock);
                    }, 800);
                }, 600);
            }
        } catch (err) {
            showToast("Error: " + (err.message || err));
            updateProgress("Failed: " + err, 0);
        } finally {
            btnStart.disabled = false;
            document.getElementById("engine-status").textContent = "Engine Ready";
        }
    });

    // Toggle Table
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

    // Table Search Filter
    const searchInput = document.getElementById("table-search");
    searchInput.addEventListener("input", (e) => {
        const query = e.target.value.toLowerCase();
        const rows = document.querySelectorAll("#candidates-tbody tr");
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(query) ? "" : "none";
        });
    });

    // Copy Working Email Button
    document.getElementById("btn-copy-hero").addEventListener("click", () => {
        const email = document.getElementById("hero-email").textContent;
        navigator.clipboard.writeText(email).then(() => {
            showToast("Copied: " + email);
        });
    });

    // Open Results Folder
    const openFolder = () => {
        if (window.go && window.go.main && window.go.main.App && window.go.main.App.OpenResultsFolder) {
            window.go.main.App.OpenResultsFolder().catch(err => showToast(err));
        } else {
            showToast("Results saved in local ./results/ directory");
        }
    };

    document.getElementById("btn-results-folder").addEventListener("click", openFolder);
    document.getElementById("btn-open-folder-action").addEventListener("click", openFolder);

    // Open Visual HTML Report in Browser
    document.getElementById("btn-open-report-web").addEventListener("click", () => {
        if (!currentResult) return;
        if (window.go && window.go.main && window.go.main.App && window.go.main.App.OpenHTMLReport) {
            window.go.main.App.OpenHTMLReport(currentResult.target_domain, currentResult.person.first_name).catch(err => showToast(err));
        } else {
            showToast("Opening browser report...");
        }
    });

    // Intercept clicks on external links to open directly in OS default browser
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
});

function updateProgress(message, pct) {
    const msgEl = document.getElementById("progress-message");
    const pctEl = document.getElementById("progress-percentage");
    const fillEl = document.getElementById("progress-bar-fill");

    if (msgEl) msgEl.textContent = message;
    if (pctEl) pctEl.textContent = pct + "%";
    if (fillEl) fillEl.style.width = pct + "%";
}

function renderResults(result) {
    currentResult = result;
    const progressCard = document.getElementById("progress-card");
    const resultsSection = document.getElementById("results-section");

    progressCard.classList.add("hidden");
    resultsSection.classList.remove("hidden");

    // Primary Hero
    const best = result.best_candidate || (result.candidates && result.candidates[0]);
    if (best) {
        document.getElementById("hero-email").textContent = best.email;
        document.getElementById("hero-confidence").textContent = (best.confidence || 95) + "% Confidence";
        document.getElementById("hero-target-name").textContent = result.person.full_name;
        document.getElementById("hero-pattern").textContent = best.pattern_name;
        
        const statusEl = document.getElementById("hero-status");
        statusEl.textContent = best.status;
        statusEl.className = "badge " + getBadgeClass(best.status);

        document.getElementById("hero-diag").textContent = best.smtp_message || "Standard corporate pattern match";
    }

    // Overview Grid
    document.getElementById("res-domain").textContent = result.target_domain;
    document.getElementById("res-provider").textContent = result.provider ? result.provider.name : "Standard SMTP";
    document.getElementById("res-mx").textContent = (result.mx_records && result.mx_records.length > 0) ? result.mx_records[0].host : "None";
    document.getElementById("res-port25").textContent = result.port_25_open ? "✔ Open / Reachable" : "✖ Blocked by ISP";

    // Candidates Table
    const tbody = document.getElementById("candidates-tbody");
    tbody.innerHTML = "";

    if (result.candidates) {
        document.getElementById("table-summary").textContent = `${result.candidates.length} permutations evaluated`;
        result.candidates.forEach((c, idx) => {
            const tr = document.createElement("tr");
            const codeStr = c.smtp_code ? String(c.smtp_code) : "-";
            const diagStr = c.smtp_message || "";
            tr.innerHTML = `
                <td>${idx + 1}</td>
                <td><strong style="color: #fff;">${escapeHtml(c.email)}</strong></td>
                <td><code>${escapeHtml(c.pattern_name)}</code></td>
                <td><span style="color: var(--accent-sky); font-weight: 700;">${c.confidence || 0}%</span></td>
                <td><span class="badge ${getBadgeClass(c.status)}">${escapeHtml(c.status)}</span></td>
                <td>${codeStr}</td>
                <td><small style="color: var(--text-muted);">${escapeHtml(diagStr)}</small></td>
            `;
            tbody.appendChild(tr);
        });
    }

    // Export Paths Notice
    const baseName = `results/${result.target_domain}_${result.person.first_name.toLowerCase()}`;
    document.getElementById("export-paths").textContent = `${baseName}_report.html`;
}

function getBadgeClass(status) {
    const s = String(status).toUpperCase();
    if (s.includes("VALID") && !s.includes("UNVERIFIED")) return "badge-valid";
    if (s.includes("INVALID") || s.includes("REJECTED")) return "badge-invalid";
    return "badge-unverified";
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

function createMockResult(domain, name, preferredPattern) {
    const fn = (name.split(" ")[0] || "user").toLowerCase();
    const ln = (name.split(" ")[1] || "name").toLowerCase();
    const pat = preferredPattern || "first.last";

    let email = `${fn}.${ln}@${domain}`;
    if (pat === "first") email = `${fn}@${domain}`;
    else if (pat === "flast") email = `${fn[0]}${ln}@${domain}`;
    else if (pat === "firstlast") email = `${fn}${ln}@${domain}`;

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
            confidence: 90,
            status: "TOP CANDIDATE (90%)",
            smtp_message: "Port 25 blocked by ISP; Selected based on " + (preferredPattern ? "user pattern preference" : "standard provider heuristics")
        },
        candidates: [
            { email: email, pattern_name: pat, confidence: 90, status: "TOP CANDIDATE", smtp_message: "Selected pattern" },
            { email: `${fn}.${ln}@${domain}`, pattern_name: "first.last", confidence: pat === "first.last" ? 90 : 60, status: "UNVERIFIED", smtp_message: "Port 25 blocked" },
            { email: `${fn}@${domain}`, pattern_name: "first", confidence: pat === "first" ? 90 : 50, status: "UNVERIFIED", smtp_message: "Port 25 blocked" }
        ]
    };
}
