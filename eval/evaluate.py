"""
Run the query/matching tool against the labeled validation set and report
top-1 and top-5 accuracy.

top-1 accuracy: the highest-scoring predicted technique is one of the labeled
                correct techniques for that example.
top-5 accuracy: any of the top-5 predicted techniques is one of the labeled
                correct techniques for that example.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from query import get_model, load_index, top_matches  # noqa: E402

EVAL_DIR = os.path.dirname(__file__)
VALIDATION_SET = os.path.join(EVAL_DIR, "validation_set.json")
RESULTS_OUT = os.path.join(EVAL_DIR, "results.json")

TOP_K = 5


def load_validation_set() -> list[dict]:
    with open(VALIDATION_SET, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate() -> dict:
    examples = load_validation_set()
    model = get_model()
    embeddings, ids, techniques = load_index()

    per_example = []
    top1_hits = 0
    top5_hits = 0

    for ex in examples:
        predictions = top_matches(
            ex["text"],
            top_k=TOP_K,
            model=model,
            embeddings=embeddings,
            ids=ids,
            techniques=techniques,
        )
        predicted_ids = [p["technique_id"] for p in predictions]
        correct = set(ex["correct_techniques"])

        top1_hit = predicted_ids[0] in correct
        top5_hit = any(pid in correct for pid in predicted_ids)

        top1_hits += int(top1_hit)
        top5_hits += int(top5_hit)

        per_example.append(
            {
                "id": ex["id"],
                "source": ex["source"],
                "correct_techniques": ex["correct_techniques"],
                "predicted": predictions,
                "top1_hit": top1_hit,
                "top5_hit": top5_hit,
            }
        )

    n = len(examples)
    summary = {
        "n_examples": n,
        "top1_accuracy": top1_hits / n,
        "top5_accuracy": top5_hits / n,
        "results": per_example,
    }
    return summary


def main():
    summary = evaluate()

    print(f"\nEvaluated {summary['n_examples']} labeled examples\n")
    print(f"Top-1 accuracy: {summary['top1_accuracy']:.1%} ({sum(r['top1_hit'] for r in summary['results'])}/{summary['n_examples']})")
    print(f"Top-5 accuracy: {summary['top5_accuracy']:.1%} ({sum(r['top5_hit'] for r in summary['results'])}/{summary['n_examples']})\n")

    print(f"{'ID':<5}{'Top-1':<7}{'Top-5':<7}{'Correct':<20}Top prediction")
    print("-" * 80)
    for r in summary["results"]:
        top1_mark = "hit" if r["top1_hit"] else "miss"
        top5_mark = "hit" if r["top5_hit"] else "miss"
        correct_str = ",".join(r["correct_techniques"])
        top_pred = r["predicted"][0]
        pred_str = f"{top_pred['technique_id']} {top_pred['name']} ({top_pred['score']:.3f})"
        print(f"{r['id']:<5}{top1_mark:<7}{top5_mark:<7}{correct_str:<20}{pred_str}")

    with open(RESULTS_OUT, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"\nFull results written to {RESULTS_OUT}")


if __name__ == "__main__":
    main()
