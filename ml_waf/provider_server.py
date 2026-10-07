"""Common HTTP wrapper for the optional third-party ML-WAF models.

The client/server stack always calls ``GET /?q=<payload>``.  This module
translates that stable contract to each model's native prediction API.
"""

import os
import pickle
import sys
import urllib.parse
from pathlib import Path

import joblib
import numpy as np
from sanic import Sanic, response


def _install_sklearn_compatibility_aliases():
    """Allow loading the XSS-WAF pickle created by scikit-learn 0.19."""
    try:
        import sklearn.linear_model._logistic as logistic
        sys.modules.setdefault("sklearn.linear_model.logistic", logistic)
    except ImportError:
        pass


_install_sklearn_compatibility_aliases()


ROOT = Path(__file__).resolve().parent
VENDOR = ROOT
PROVIDER = os.environ.get("ML_WAF_PROVIDER", "wafbrain").strip().lower()


def _clean(payload: str) -> str:
    """Use the same basic normalization expected by the source classifiers."""
    previous = payload
    for _ in range(100):
        current = urllib.parse.unquote_plus(previous)
        if current == previous:
            break
        previous = current
    return " ".join(previous.strip().split()).lower()


class ModelProvider:
    def __init__(self, name: str):
        self.name = name
        if name == "ml_based_waf":
            base = VENDOR / "ml_based_waf" / "Classifier"
            self.model = joblib.load(base / "predictor.joblib")
            # The bundled SVC was serialized with scikit-learn 0.22.1. Newer
            # versions expect these probability arrays to exist even when the
            # original classifier was trained without probability estimates.
            classifier = self.model.steps[-1][1]
            if not hasattr(classifier, "_probA"):
                classifier._probA = np.array([])
            if not hasattr(classifier, "_probB"):
                classifier._probB = np.array([])
        elif name == "xss_waf":
            model_path = VENDOR / "xss_waf" / "waf" / "trained_waf_model"
            with model_path.open("rb") as model_file:
                self.model = pickle.load(model_file)
        else:
            raise ValueError(f"Unsupported external provider: {name}")

    def classify(self, payload: str):
        text = _clean(payload)
        if self.name == "ml_based_waf":
            label = str(self.model.predict([text])[0])
            malicious = label.lower() not in {"valid", "benign", "normal", "0"}
            return malicious, label, None

        probabilities = self.model.predict_proba([text])[0]
        classes = list(getattr(self.model, "classes_", [0, 1]))
        malicious_index = classes.index(1) if 1 in classes else len(classes) - 1
        confidence = float(probabilities[malicious_index])
        return confidence >= 0.5, ("malicious" if confidence >= 0.5 else "benign"), confidence


if PROVIDER not in {"ml_based_waf", "xss_waf"}:
    raise SystemExit(f"provider_server cannot run provider '{PROVIDER}'")

provider = ModelProvider(PROVIDER)
app = Sanic("ml_waf_provider")


@app.get("/")
async def classify(request):
    payloads = [value for _, value in request.query_args if value is not None]
    if not payloads:
        payloads = [request.args.get("q", "")]

    results = [provider.classify(payload) for payload in payloads]
    blocked = any(item[0] for item in results)
    body = {
        "provider": PROVIDER,
        "prediction": "malicious" if blocked else "benign",
        "results": [
            {"prediction": label, "confidence": confidence}
            for _, label, confidence in results
        ],
    }
    return response.json(body, status=403 if blocked else 200)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, access_log=False)
