import json
import os
from pathlib import Path
from urllib import parse, request

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException

from drift_monitor import FeatureDriftMonitor
from feature_contract import FEATURE_COLUMNS
from LureGuardExtractor import LureGuardExtractor, parse_event_datetime
from WazuhAlert import WazuhAlert
from whitelist import WhitelistChecker

app = FastAPI()

ARTIFACTS_DIR = Path("artifacts")
MODEL_PATH = ARTIFACTS_DIR / "model.joblib"
SCALER_PATH = ARTIFACTS_DIR / "scaler.joblib"
METRICS_PATH = ARTIFACTS_DIR / "metrics.json"
WHITELIST_PATH = ARTIFACTS_DIR / "whitelist.json"
TEMPORAL_BASELINE_PATH = ARTIFACTS_DIR / "temporal_baseline.json"
DRIFT_BASELINE_PATH = ARTIFACTS_DIR / "drift_baseline.json"

extractor = LureGuardExtractor(
    window_seconds=300,
    burst_subwindow_seconds=10,
    baseline_min_count=30,
    baseline_store_path=TEMPORAL_BASELINE_PATH,
)
whitelist_checker = WhitelistChecker(WHITELIST_PATH)
drift_monitor = FeatureDriftMonitor(DRIFT_BASELINE_PATH)

model = None
scaler = None
block_threshold = 0.5
alert_threshold = 0.3


def _get_float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


class TelegramNotifier:
    def __init__(self) -> None:
        self.token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
        self.timeout_seconds = _get_float_env("TELEGRAM_TIMEOUT_SECONDS", 3.0)

    @property
    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    def send_alert(self, message: str) -> dict:
        if not self.enabled:
            return {"sent": False, "reason": "telegram_not_configured"}

        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        body = parse.urlencode({"chat_id": self.chat_id, "text": message}).encode("utf-8")

        req = request.Request(url=url, data=body, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))

            is_ok = bool(payload.get("ok"))
            return {
                "sent": is_ok,
                "reason": "ok" if is_ok else "telegram_api_error",
            }
        except Exception as exc:
            return {
                "sent": False,
                "reason": f"telegram_send_failed: {type(exc).__name__}",
            }


telegram_notifier = TelegramNotifier()


def load_artifacts() -> None:
    global model, scaler, block_threshold, alert_threshold

    if not MODEL_PATH.exists() or not SCALER_PATH.exists() or not METRICS_PATH.exists():
        raise FileNotFoundError(
            f"Missing artifacts. Expected {MODEL_PATH}, {SCALER_PATH}, and {METRICS_PATH}"
        )

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    block_threshold = float(metrics["training"]["test_tuned_threshold"]["threshold"])

    alert_threshold = _get_float_env("ALERT_THRESHOLD", min(0.3, block_threshold))
    if alert_threshold >= block_threshold:
        alert_threshold = max(0.0, block_threshold - 1e-6)


@app.on_event("startup")
async def startup_event() -> None:
    load_artifacts()


@app.post("/wazuh/event")
async def handle_event(alert: WazuhAlert):
    if model is None or scaler is None:
        raise HTTPException(status_code=500, detail="Model artifacts not loaded")

    src_ip = str(alert.data.get("srcip", ""))
    src_user = str(alert.data.get("srcuser", ""))
    event_dt = parse_event_datetime(getattr(alert, "timestamp", None))
    is_whitelisted = whitelist_checker.is_whitelisted(src_ip, src_user, event_dt)

    x = extractor.update_and_extract(alert, is_whitelist=is_whitelisted)

    x_df = pd.DataFrame([x], columns=FEATURE_COLUMNS)
    x_scaled = scaler.transform(x_df)
    risk_score = float(model.predict_proba(x_scaled)[0, 1])

    if is_whitelisted:
        # Fail-safe whitelist override.
        risk_score = 0.0

    if risk_score >= block_threshold:
        decision = "block"
    elif risk_score >= alert_threshold:
        decision = "alert"
    else:
        decision = "allow"

    predicted_label = int(decision == "block")

    telegram_status = None
    if decision == "alert":
        message = (
            "LureGuard Alert\n"
            f"src_ip={src_ip or 'unknown'}\n"
            f"src_user={src_user or 'unknown'}\n"
            f"risk_score={risk_score:.4f}\n"
            f"alert_threshold={alert_threshold:.4f}\n"
            f"block_threshold={block_threshold:.4f}"
        )
        telegram_status = telegram_notifier.send_alert(message)

    feature_map = dict(zip(FEATURE_COLUMNS, x))
    drift_state = drift_monitor.update(feature_map)

    return {
        "status": "processed",
        "src_ip": alert.data.get("srcip"),
        "features": x,
        "risk_score": risk_score,
        "thresholds": {
            "alert": alert_threshold,
            "block": block_threshold,
        },
        "predicted_label": predicted_label,
        "decision": decision,
        "telegram": telegram_status,
        "is_whitelisted": is_whitelisted,
        "drift_monitor": drift_state,
    }
