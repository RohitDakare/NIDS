"""
Validate existing .joblib models by loading them and performing a sanity-check prediction
with a synthetic PacketInfo instance via MLDetector.
"""
import os
import glob
import json
import logging
from datetime import datetime
from typing import List

from app.core.ml_detector import MLDetector
from app.models.schemas import PacketInfo, MLModelConfig

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("validate_model")


def find_models(paths: List[str]) -> List[str]:
    models = []
    for p in paths:
        models.extend(glob.glob(p, recursive=True))
    # Deduplicate while preserving order
    seen = set()
    uniq = []
    for m in models:
        if m not in seen and os.path.isfile(m) and m.lower().endswith('.joblib'):
            seen.add(m)
            uniq.append(m)
    return uniq


def make_synthetic_packet(i: int = 0) -> PacketInfo:
    now = datetime.now()
    return PacketInfo(
        timestamp=now,
        source_ip=f"192.168.1.{(i % 200) + 1}",
        dest_ip=f"10.0.0.{(i % 200) + 1}",
        protocol='TCP' if i % 2 == 0 else 'UDP',
        source_port=10000 + (i % 1000),
        dest_port=80 if i % 2 == 0 else 443,
        packet_length=60 + (i % 1400),
        tcp_flags="SYN" if i % 3 == 0 else "ACK",
        payload_size=0 if i % 5 == 0 else 512,
    )


def validate_model(model_path: str) -> dict:
    logger.info(f"Validating model: {model_path}")
    detector = MLDetector.load_model(model_path)
    if detector is None:
        return {"model": model_path, "status": "failed_to_load"}

    pkt = make_synthetic_packet()
    is_anom, conf, info = detector.predict(pkt)
    return {
        "model": model_path,
        "status": "ok",
        "prediction": bool(is_anom),
        "confidence": float(conf),
        "model_info": info,
    }


def main():
    search_paths = [
        "app/ml_models/**/*.joblib",
        "models/**/*.joblib",
    ]
    model_paths = find_models(search_paths)

    if not model_paths:
        logger.warning("No .joblib models found in app/ml_models/ or models/.")
        return

    results = []
    for mp in model_paths:
        try:
            results.append(validate_model(mp))
        except Exception as e:
            logger.exception(f"Error validating {mp}: {e}")
            results.append({"model": mp, "status": "error", "error": str(e)})

    print(json.dumps({"results": results}, indent=2))


if __name__ == "__main__":
    main()
