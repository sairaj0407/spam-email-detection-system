"""Retrain TF-IDF + logistic model from stored email labels."""
from __future__ import annotations

from pathlib import Path

import joblib
import train_model as synthetic_corpus
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from models import EmailRecord
from text_utils import preprocess


def retrain_and_save(model_dir: Path) -> dict:
    texts: list[str] = []
    labels: list[int] = []

    for r in EmailRecord.query.all():
        p = preprocess(r.email_text or "")
        if not p:
            continue
        texts.append(p)
        labels.append(1 if r.prediction == "Spam" else 0)

    used_synthetic = False
    if len(texts) < 12 or len(set(labels)) < 2:
        used_synthetic = True
        for t in synthetic_corpus.HAM:
            texts.append(preprocess(t))
            labels.append(0)
        for t in synthetic_corpus.SPAM:
            texts.append(preprocess(t))
            labels.append(1)

    if len(set(labels)) < 2:
        return {
            "ok": False,
            "error": "Not enough diverse labels to train.",
            "n_samples": len(texts),
        }

    vec = TfidfVectorizer(
        lowercase=False,
        stop_words="english",
        max_df=0.85,
        min_df=2,
        max_features=10000,
        ngram_range=(1, 2),
        sublinear_tf=True,
    )
    X = vec.fit_transform(texts)
    y = labels
    accuracy = precision = recall = f1 = None

    clf = LogisticRegression(
        max_iter=3000,
        random_state=42,
        class_weight="balanced",
        solver="liblinear",
    )

    if len(y) >= 24:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        clf.fit(X_train, y_train)
        pred = clf.predict(X_test)
        accuracy = round(float(accuracy_score(y_test, pred)) * 100, 2)
        precision = round(float(precision_score(y_test, pred, zero_division=0)) * 100, 2)
        recall = round(float(recall_score(y_test, pred, zero_division=0)) * 100, 2)
        f1 = round(float(f1_score(y_test, pred, zero_division=0)) * 100, 2)
    else:
        clf.fit(X, y)

    joblib.dump(clf, model_dir / "model.pkl")
    joblib.dump(vec, model_dir / "vectorizer.pkl")

    result = {
        "ok": True,
        "n_samples": len(texts),
        "used_synthetic_fallback": used_synthetic,
        "message": "Model and vectorizer saved.",
    }
    if accuracy is not None:
        result.update(
            {
                "accuracy_percent": accuracy,
                "precision_percent": precision,
                "recall_percent": recall,
                "f1_percent": f1,
            }
        )

    return result
