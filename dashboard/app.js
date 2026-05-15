document.addEventListener("DOMContentLoaded", () => {
    const state = {
        file: null,
        fileName: "No file selected",
        detectedType: "Waiting for scan",
        mime: "Waiting for scan",
        size: "Waiting for scan",
        firstSeen: "Waiting for scan",
        lastModified: "Waiting for scan",
        created: "Browser upload cannot safely read this",
        hash: "Waiting for scan",
        magic: "Waiting for scan",
        score: 0,
        severity: "Waiting",
        action: "Waiting for file scan",
        recommendation: "Upload and scan a file to generate the analysis.",
        reasons: ["Waiting for file scan"]
    };

    const $ = (selector) => document.querySelector(selector);
    const $$ = (selector) => Array.from(document.querySelectorAll(selector));
    const byId = (id) => document.getElementById(id);

    function setText(id, value) {
        $$(`#${id}`).forEach((element) => {
            element.textContent = value;
        });
    }

    function setHTML(id, value) {
        $$(`#${id}`).forEach((element) => {
            element.innerHTML = value;
        });
    }

    function addFlash(id) {
        const element = byId(id);
        if (!element) return;
        element.classList.remove("scan-updated");
        void element.offsetWidth;
        element.classList.add("scan-updated");
    }

    function formatBytes(bytes) {
        if (!bytes) return "0 B";
        const units = ["B", "KB", "MB", "GB"];
        const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
        const value = bytes / Math.pow(1024, index);
        return `${value.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
    }

    function formatDate(value) {
        if (!value) return "Not available";
        return new Date(value).toLocaleString();
    }

    function nowStamp() {
        return new Date().toLocaleString();
    }

    function extensionOf(fileName) {
        const parts = String(fileName).toLowerCase().split(".");
        return parts.length > 1 ? parts.pop() : "";
    }

    function hexFromBuffer(buffer, maxBytes = 16) {
        return Array.from(new Uint8Array(buffer.slice(0, maxBytes)))
            .map((byte) => byte.toString(16).padStart(2, "0").toUpperCase())
            .join(" ");
    }

    async function getMagicBytes(file) {
        const buffer = await file.slice(0, 16).arrayBuffer();
        return hexFromBuffer(buffer, 12);
    }

    async function getSha256(file) {
        if (!crypto || !crypto.subtle) {
            return "SHA-256 unavailable in this browser context";
        }

        const buffer = await file.arrayBuffer();
        const digest = await crypto.subtle.digest("SHA-256", buffer);

        return Array.from(new Uint8Array(digest))
            .map((byte) => byte.toString(16).padStart(2, "0"))
            .join("");
    }

    async function readSafeTextPreview(file) {
        const maxBytes = Math.min(file.size, 1024 * 512);
        try {
            return await file.slice(0, maxBytes).text();
        } catch {
            return "";
        }
    }

    function detectFileType(fileName, magic, mime) {
        const ext = extensionOf(fileName);

        if (["xlsm", "docm", "pptm"].includes(ext)) return `Microsoft Office Macro-Enabled (.${ext})`;
        if (["xlsx", "docx", "pptx"].includes(ext)) return `Microsoft Office Document (.${ext})`;
        if (["exe", "dll", "scr"].includes(ext)) return `Windows Binary (.${ext})`;
        if (["ps1", "bat", "cmd", "vbs", "js", "jar"].includes(ext)) return `Script Or Executable (.${ext})`;
        if (["zip", "rar", "7z"].includes(ext)) return `Archive (.${ext})`;
        if (ext === "pdf") return "PDF Document (.pdf)";
        if (["txt", "csv", "json", "xml", "html", "css", "md"].includes(ext)) return `Text-Based File (.${ext})`;
        if (["jpg", "jpeg", "png", "webp", "gif", "svg"].includes(ext)) return `Image File (.${ext})`;

        if (magic.startsWith("4D 5A")) return "Windows PE Binary";
        if (magic.startsWith("D0 CF 11 E0")) return "OLE Office Document";
        if (magic.startsWith("50 4B")) return "ZIP-Based Container";
        if (magic.startsWith("25 50 44 46")) return "PDF Document";
        if (mime) return mime;

        return ext ? `Unknown File (.${ext})` : "Unknown File";
    }

    function setSelectValue(selectId, value) {
        const select = byId(selectId);
        if (!select) return;

        const existing = Array.from(select.options).find((option) => option.value === value || option.textContent === value);

        if (existing) {
            select.value = existing.value;
            return;
        }

        const option = document.createElement("option");
        option.value = value;
        option.textContent = value;
        select.appendChild(option);
        select.value = value;
    }

    function getCheckbox(id) {
        const element = byId(id);
        return element ? element.checked : false;
    }

    function scoreFile(meta, previewText = "") {
        let score = 8;
        const reasons = [];
        const fileName = meta.fileName.toLowerCase();
        const ext = extensionOf(fileName);
        const text = previewText.toLowerCase();

        if (getCheckbox("externalSource")) {
            score += 12;
            reasons.push("External source selected");
        }

        if (["xlsm", "docm", "pptm"].includes(ext)) {
            score += 28;
            reasons.push("Macro-enabled Office file");
        }

        if (["exe", "dll", "scr", "ps1", "bat", "cmd", "vbs", "js", "jar"].includes(ext)) {
            score += 32;
            reasons.push("Executable or script-like file type");
        }

        if (["zip", "rar", "7z"].includes(ext)) {
            score += 14;
            reasons.push("Archive container needs controlled review");
        }

        if (ext === "pdf") {
            score += 8;
            reasons.push("PDF file, safe static review recommended");
        }

        if (["invoice", "payment", "urgent", "update", "password", "login", "confirm", "refund", "benefits", "cover letter"].some((word) => fileName.includes(word))) {
            score += 10;
            reasons.push("Filename contains business or urgency wording");
        }

        if (meta.magic.startsWith("4D 5A")) {
            score += 30;
            reasons.push("MZ executable header detected");
        }

        if (meta.magic.startsWith("D0 CF 11 E0")) {
            score += 18;
            reasons.push("OLE Office header detected");
        }

        if (meta.magic.startsWith("50 4B")) {
            score += 8;
            reasons.push("ZIP-based container header detected");
        }

        if (text.includes("/javascript") || text.includes("/openaction") || text.includes("/launch") || text.includes("/embeddedfile")) {
            score += 24;
            reasons.push("PDF action or embedded content marker found");
        }

        if (text.includes("powershell") || text.includes("cmd.exe") || text.includes("wscript") || text.includes("base64")) {
            score += 22;
            reasons.push("Script-like command text found in safe preview");
        }

        if (meta.file.size > 25 * 1024 * 1024) {
            score += 8;
            reasons.push("Large file size increases handling complexity");
        }

        if (reasons.length === 0) {
            reasons.push("No major static warning found");
        }

        score = Math.min(score, 100);

        let severity = "Low";
        let action = "Archive";
        let recommendation = "Low-risk static indicators. Archive unless new evidence appears.";

        if (score >= 75) {
            severity = "Critical";
            action = "Immediate Analysis";
            recommendation = "High risk detected. Route to sandbox and senior review. Do not execute the file.";
        } else if (score >= 50) {
            severity = "High";
            action = "Route To Sandbox";
            recommendation = "Elevated risk detected. Route to sandbox for controlled review.";
        } else if (score >= 25) {
            severity = "Medium";
            action = "Manual Review";
            recommendation = "Moderate risk. Review evidence and decide whether sandbox routing is needed.";
        }

        return { score, severity, action, recommendation, reasons };
    }

    function updateRiskBars(score) {
        const values = {
            factorMalicious: Math.min(99, Math.max(5, score + 4)),
            factorMacro: Math.min(99, Math.max(5, score - 6)),
            factorReputation: Math.min(99, Math.max(5, score - 14)),
            factorBehavior: Math.min(99, Math.max(5, score + 2)),
            factorIntel: Math.min(99, Math.max(5, score - 8))
        };

        Object.entries(values).forEach(([id, value]) => {
            setText(id, value);
            const element = byId(id);
            const bar = element?.parentElement?.querySelector("i");
            if (bar) bar.style.setProperty("--w", `${value}%`);
        });
    }

    function updateScoreDial(score, severity) {
        const color =
            severity === "Critical" ? "var(--red)" :
            severity === "High" ? "var(--amber)" :
            severity === "Medium" ? "var(--purple)" :
            "var(--green)";

        const scoreDial = byId("scoreDial");
        if (scoreDial) {
            scoreDial.style.background =
                `radial-gradient(circle at center, rgba(255,255,255,.08) 0 46%, transparent 47%), conic-gradient(${color} 0 ${score}%, rgba(255,255,255,.08) 0)`;
        }

        const mini = byId("navAnalysisScore")?.closest(".big-score-mini");
        if (mini) {
            mini.style.background =
                `radial-gradient(circle at center, rgba(8,19,25,.96) 0 48%, transparent 49%), conic-gradient(${color} 0 ${score}%, rgba(255,255,255,.08) 0)`;
        }
    }

    function updateAllScreens() {
        setText("scoreNumber", state.score || "--");
        setText("scoreSeverity", state.severity);
        setText("chartBadge", state.score || "--");
        setText("classification", state.severity === "Low" ? "Low Risk" : state.severity === "Medium" ? "Suspicious" : state.severity === "High" ? "Elevated Risk" : "High-Risk Sample");

        setText("recommendedTitle", state.action);
        setText("recommendedText", state.recommendation);

        setText("eSource", byId("sourceChannel")?.value || "Manual Upload");
        setText("eFile", state.fileName);
        setText("eType", state.detectedType);
        setText("eMime", state.mime);
        setText("eSize", state.size);
        setText("eFirstSeen", state.firstSeen);
        setText("eLastModified", state.lastModified);
        setText("eCreated", state.created);
        setText("eHash", state.hash);
        setText("eMagic", state.magic);

        setText("pName", state.fileName);
        setText("pType", state.detectedType);
        setText("pMime", state.mime);
        setText("pSize", state.size);
        setText("pFirstSeen", state.firstSeen);
        setText("pLastModified", state.lastModified);
        setText("pCreated", state.created);
        setText("pHash", state.hash);
        setText("pMagic", state.magic);
        setText("autoStatus", state.file ? "Detected" : "Waiting for upload");

        const hintsHtml = state.reasons.map((reason) => `<span>${reason}</span>`).join("");
        setHTML("pRiskHints", hintsHtml);
        setHTML("navAnalysisHints", hintsHtml);

        setText("navIntakeFile", state.fileName);
        setText("navIntakeType", state.detectedType);
        setText("navIntakeSize", state.size);
        setText("navIntakeHash", state.hash);
        setText("navIntakeStatus", state.file ? "File detected and scanned" : "Ready for file upload");

        setText("navAnalysisScore", state.score || "--");
        setText("navAnalysisSeverity", state.severity);
        setText("navAnalysisReason", state.recommendation);

        setText("navEvidenceFile", state.fileName);
        setText("navEvidenceType", state.detectedType);
        setText("navEvidenceHash", state.hash);
        setText("navEvidenceMagic", state.magic);

        setText("reportSummary", state.file
            ? `${state.fileName} was scanned using safe static analysis. Current score: ${state.score} (${state.severity}). Recommendation: ${state.recommendation}`
            : "No uploaded file report yet. Upload and scan a file to generate a summary."
        );

        setText("sandboxFileName", state.fileName);
        setText("sandboxHash", state.hash);
        setText("sandboxQueue", state.file
            ? state.score >= 75 ? "Critical Sandbox Queue" : state.score >= 50 ? "Standard Sandbox Queue" : "Sandbox Record Created"
            : "Waiting"
        );
        setText("sandboxResult", state.file
            ? `Sandbox routing record created. Current risk: ${state.score} (${state.severity}). Execution disabled in demo mode.`
            : "No sandbox record yet"
        );
        setText("sandboxStatusTitle", state.file ? "File routed to sandbox queue" : "Waiting for uploaded file");
        setText("sandboxStatusText", state.file
            ? "SentinelQueue created a safe sandbox routing record. This portfolio demo does not execute the file."
            : "Upload and scan a file from the Command Center."
        );

        const sandboxProgress = $(".sandbox-progress");
        if (sandboxProgress) sandboxProgress.classList.toggle("active", Boolean(state.file));

        updateRiskBars(state.score || 0);
        updateScoreDial(state.score || 0, state.severity);

        addFlash("scoreDial");
        addFlash("page-analysis");
        addFlash("page-sandbox");
    }

    async function loadFile(file) {
        state.file = file;
        state.fileName = file.name;
        state.size = formatBytes(file.size);
        state.mime = file.type || "Browser did not provide MIME type";
        state.firstSeen = nowStamp();
        state.lastModified = formatDate(file.lastModified);
        state.created = "Browser upload cannot safely read this";
        state.magic = await getMagicBytes(file);

        const fullHash = await getSha256(file);
        state.hash = fullHash.length > 32 ? `${fullHash.slice(0, 16)}...${fullHash.slice(-16)}` : fullHash;

        state.detectedType = detectFileType(file.name, state.magic, file.type);

        const fileNameInput = byId("fileName");
        if (fileNameInput) fileNameInput.value = state.fileName;

        setSelectValue("fileType", state.detectedType);

        const dropZone = byId("dropZone");
        const dropTitle = byId("dropTitle");
        const fileReadout = byId("fileReadout");

        if (dropZone) dropZone.classList.add("file-loaded");
        if (dropTitle) dropTitle.textContent = state.fileName;

        if (fileReadout) {
            fileReadout.innerHTML = `
                <b>Loaded:</b> ${state.fileName}<br>
                <b>Detected:</b> ${state.detectedType}<br>
                <b>Size:</b> ${state.size}<br>
                <b>Last Modified:</b> ${state.lastModified}<br>
                <b>SHA-256:</b> ${state.hash}
            `;
        }

        await runScan();
    }

    async function runScan() {
        let preview = "";

        if (state.file) {
            preview = await readSafeTextPreview(state.file);
        }

        const result = state.file
            ? scoreFile(state, preview)
            : {
                score: 0,
                severity: "Waiting",
                action: "Waiting for file scan",
                recommendation: "Upload and scan a file to generate the analysis.",
                reasons: ["Waiting for file scan"]
            };

        state.score = result.score;
        state.severity = result.severity;
        state.action = result.action;
        state.recommendation = result.recommendation;
        state.reasons = result.reasons;

        updateAllScreens();
    }

    function showPage(pageName) {
        const page = String(pageName || "command").toLowerCase();

        $$(".main-nav nav a").forEach((link) => {
            link.classList.toggle("active", link.dataset.page === page);
        });

        const coreSelectors = [
            ".mission-hero",
            ".stats-row",
            ".step-ribbon",
            ".workflow-grid",
            ".process-strip",
            ".testimonial",
            ".footer-status"
        ];

        const showCommand = page === "command";

        coreSelectors.forEach((selector) => {
            $$(selector).forEach((section) => {
                if (!section.classList.contains("nav-page")) {
                    section.classList.toggle("page-hidden", !showCommand);
                }
            });
        });

        $$(".nav-page").forEach((section) => {
            section.classList.add("page-hidden");
        });

        if (!showCommand) {
            const target = byId(`page-${page}`);
            if (target) target.classList.remove("page-hidden");
        }

        window.scrollTo({ top: 0, behavior: "smooth" });
    }

    document.addEventListener("click", async (event) => {
        const navLink = event.target.closest(".main-nav nav a");
        if (navLink) {
            event.preventDefault();
            showPage(navLink.dataset.page);
            return;
        }

        const selectButton = event.target.closest("#selectFilesButton");
        if (selectButton) {
            event.preventDefault();
            byId("realFileInput")?.click();
            return;
        }
    });

    const fileInput = byId("realFileInput");
    if (fileInput) {
        fileInput.addEventListener("change", async () => {
            const file = fileInput.files?.[0];
            if (file) await loadFile(file);
        });
    }

    const dropZone = byId("dropZone");
    if (dropZone) {
        dropZone.addEventListener("dragover", (event) => {
            event.preventDefault();
            dropZone.classList.add("drag-active");
        });

        dropZone.addEventListener("dragleave", () => {
            dropZone.classList.remove("drag-active");
        });

        dropZone.addEventListener("drop", async (event) => {
            event.preventDefault();
            dropZone.classList.remove("drag-active");

            const file = event.dataTransfer.files?.[0];
            if (file) await loadFile(file);
        });
    }

    const form = byId("sampleForm");
    if (form) {
        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            await runScan();

            const stepTwo = document.querySelector(".step-two");
            if (stepTwo) {
                stepTwo.scrollIntoView({ behavior: "smooth", block: "start" });
            }
        });
    }

    $$(".action-option").forEach((button) => {
        button.addEventListener("click", () => {
            $$(".action-option").forEach((item) => item.classList.remove("selected"));
            button.classList.add("selected");

            const queue = byId("queueSelect");
            if (!queue) return;

            queue.value =
                button.dataset.action === "Route To Sandbox" ? "Sandbox Priority Queue" :
                button.dataset.action === "Escalate" ? "Critical Queue" :
                button.dataset.action === "Monitor" ? "Analyst Review Queue" :
                "Passive Archive";
        });
    });

    updateAllScreens();
});
