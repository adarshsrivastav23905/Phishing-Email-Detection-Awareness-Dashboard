"""Optional ML training helper for the phishing dashboard project.

This module is intentionally lightweight and educational. It demonstrates how a text-based
classifier can be trained on synthetic phishing and legitimate samples, but the core project
uses explainable rule-based scoring as the primary decision engine.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .config import DATASET_PATH

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
except ImportError as exc:  # pragma: no cover - only used when sklearn is absent
    raise RuntimeError("scikit-learn is required for ML training. Install requirements.txt first.") from exc


def load_dataset(path: Path = DATASET_PATH):
    records = []
    with path.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            records.append(row)
    return records


def train_ml_model(path: Path = DATASET_PATH):
    rows = load_dataset(path)
    texts = []
    labels = []
    for row in rows:
        text = f"{row.get('subject', '')} {row.get('body', '')} {row.get('sender', '')} {row.get('urls', '')}"
        texts.append(text)
        labels.append(row.get('label', 'LEGITIMATE'))

    pipeline = Pipeline(
        [
            ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1)),
            ("clf", LogisticRegression(max_iter=1000, solver="liblinear")),
        ]
    )
    pipeline.fit(texts, labels)
    return pipeline


def predict_ml_label(model, sender, subject, body, urls):
    text = f"{subject} {body} {sender} {urls}"
    return model.predict([text])[0]


if __name__ == "__main__":
    model = train_ml_model()
    print(model)
