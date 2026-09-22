/* CyberSecurity Dashboard — shared client helpers */

// --- Live clock in navbar -----------------------------------------------
(function () {
    const el = document.getElementById("clock");
    if (!el) return;
    const tick = () => {
        el.textContent = new Date().toLocaleTimeString();
    };
    tick();
    setInterval(tick, 1000);
})();

// --- CSRF helper ---------------------------------------------------------
function getCookie(name) {
    const v = document.cookie.match("(^|;)\\s*" + name + "\\s*=\\s*([^;]+)");
    return v ? v.pop() : "";
}

// --- Generic fetch wrapper ----------------------------------------------
async function apiFetch(url, options = {}) {
    const opts = Object.assign({
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCookie("csrftoken"),
        },
    }, options);
    const res = await fetch(url, opts);
    if (!res.ok) {
        const text = await res.text();
        throw new Error(`${res.status} ${res.statusText}: ${text}`);
    }
    return res.json();
}

// --- Predict a single log -----------------------------------------------
async function predictLog(logId, btn) {
    if (btn) {
        btn.disabled = true;
        btn.classList.add("loading");
    }
    try {
        const data = await apiFetch(`/api/logs/${logId}/predict/`, {
            method: "POST",
            body: "{}",
        });
        renderPredictionResult(logId, data);
    } catch (err) {
        alert("Prediction failed: " + err.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.classList.remove("loading");
        }
    }
}

function renderPredictionResult(logId, data) {
    const cell = document.getElementById(`pred-${logId}`);
    if (!cell) return;
    const label = data.is_suspicious ? "suspicious" : "benign";
    const anom = data.is_anomaly ? "anomaly" : "normal";
    cell.innerHTML = `
        <span class="pill pill-${anom}">${anom}</span>
        <span class="pill pill-${label}">${label}</span>
        <div class="small text-muted mono mt-1">
            anom=${data.anomaly_score.toFixed(3)} ·
            susp=${data.suspicion_probability.toFixed(3)}
        </div>
    `;
}

// --- Batch predict -------------------------------------------------------
async function runBatchPredict(btn) {
    if (btn) {
        btn.disabled = true;
        btn.classList.add("loading");
    }
    try {
        const data = await apiFetch("/api/logs/predict-batch/?limit=50", {
            method: "POST",
            body: "{}",
        });
        alert(
            `Batch complete.\n` +
            `Processed: ${data.processed}\n` +
            `Predictions created: ${data.predictions_created}\n` +
            `Anomalies: ${data.anomalies_detected}\n` +
            `Suspicious: ${data.suspicious_flagged}`
        );
        location.reload();
    } catch (err) {
        alert("Batch prediction failed: " + err.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.classList.remove("loading");
        }
    }
}

window.predictLog = predictLog;
window.runBatchPredict = runBatchPredict;