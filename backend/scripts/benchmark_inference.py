"""
Benchmark real-time ML inference performance using MLDetector.
This script loads an existing model (if provided) or uses the default pipeline,
then measures latency and throughput on synthetic packets.
"""
import argparse
import json
import logging

from app.core.ml_detector import MLDetector
from app.models.schemas import MLModelConfig

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("benchmark_inference")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=str, default="app/ml_models/nids_model.joblib", help="Path to .joblib model to load")
    parser.add_argument("--runs", type=int, default=500, help="Number of timed runs")
    parser.add_argument("--warmup", type=int, default=50, help="Number of warmup runs")
    args = parser.parse_args()

    detector = MLDetector.load_model(args.model)
    if detector is None:
        logger.warning("Failed to load model, creating default detector pipeline instead (untrained classifier).")
        detector = MLDetector(MLModelConfig(model_path=args.model))

    result = detector.benchmark_inference(runs=args.runs, warmup=args.warmup)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
