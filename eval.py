# evaluate_gaxss_results.py
# Versi otomatis: olah semua file XSS dan SQLi di folder results/

import os
import glob
import csv

from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)


# --- Utilitas pembaca CSV ---

def load_labels_from_csv(pattern):
    """
    Baca semua file CSV yang match pattern (glob),
    lalu ambil kolom GroundTruth dan Predicted.
    """
    y_true = []
    y_pred = []

    files = sorted(glob.glob(pattern))
    if not files:
        print(f"[WARN] Tidak ada file yang cocok dengan pattern: {pattern}")
        return y_true, y_pred

    print(f"[INFO] Membaca {len(files)} file:")
    for path in files:
        print(f"  - {path}")
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                gt = (row.get("GroundTruth") or "").strip().upper()
                pred = (row.get("Predicted") or "").strip().upper()

                # Skip baris kosong / tidak lengkap
                if not gt or not pred:
                    continue

                # Hanya terima label yang kita kenal
                if gt not in {"VULNERABLE", "SAFE"}:
                    continue
                if pred not in {"VULNERABLE", "SAFE"}:
                    continue

                y_true.append(gt)
                y_pred.append(pred)

    print(f"[INFO] Total sampel terbaca: {len(y_true)}")
    return y_true, y_pred


def print_metrics(title, y_true, y_pred):
    """
    Cetak confusion matrix + classification report
    untuk label biner VULNERABLE vs SAFE.
    """
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

    if not y_true or not y_pred:
        print("[WARN] Data kosong, tidak bisa menghitung metrik.")
        return

    labels = ["VULNERABLE", "SAFE"]

    # Confusion matrix (urut: VULNERABLE, SAFE)
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    tn = cm[1, 1]  # SAFE diprediksi SAFE
    tp = cm[0, 0]  # VULNERABLE diprediksi VULNERABLE
    fp = cm[1, 0]  # SAFE tapi diprediksi VULNERABLE
    fn = cm[0, 1]  # VULNERABLE tapi diprediksi SAFE

    print("Confusion Matrix (baris = actual, kolom = predicted)")
    print("                PREDICTED")
    print("              VULNERABLE   SAFE")
    print(f"ACTUAL VULN  {tp:10d} {fn:8d}")
    print(f"ACTUAL SAFE  {fp:10d} {tn:8d}")
    print()

    # Metrik global
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, pos_label="VULNERABLE", zero_division=0)
    rec = recall_score(y_true, y_pred, pos_label="VULNERABLE", zero_division=0)
    f1 = f1_score(y_true, y_pred, pos_label="VULNERABLE", zero_division=0)

    print("Metrik Global (positif = VULNERABLE):")
    print(f"  Accuracy : {acc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall   : {rec:.4f}")
    print(f"  F1-Score : {f1:.4f}")
    print()

    # Classification report per kelas
    print("Classification Report:")
    print(
        classification_report(
            y_true,
            y_pred,
            labels=labels,
            target_names=labels,
            digits=4,
            zero_division=0,
        )
    )


def main():
    """
    Asumsi struktur folder:
      - results/
          dvwa_xss_low.csv
          dvwa_xss_medium.csv
          ...
          bwapp_sqli_medium.csv
          mutillidae_sqli_high.csv
    """
    base_results_dir = "results"

    # --- Evaluasi XSS: semua file yang mengandung 'xss_' ---
    xss_pattern = os.path.join(base_results_dir, "*XSS_*.csv")
    y_true_xss, y_pred_xss = load_labels_from_csv(xss_pattern)
    print_metrics("HASIL EVALUASI XSS (SEMUA TEST CASE)", y_true_xss, y_pred_xss)

    # --- Evaluasi SQLi: semua file yang mengandung 'sqli_' ---
    sqli_pattern = os.path.join(base_results_dir, "*SQLi_*.csv")
    y_true_sqli, y_pred_sqli = load_labels_from_csv(sqli_pattern)
    print_metrics("HASIL EVALUASI SQL INJECTION (SEMUA TEST CASE)", y_true_sqli, y_pred_sqli)

    # --- Gabungan semua ---
    if y_true_xss and y_true_sqli:
        y_true_all = y_true_xss + y_true_sqli
        y_pred_all = y_pred_xss + y_pred_sqli
        print_metrics("HASIL EVALUASI GABUNGAN (XSS + SQLi)", y_true_all, y_pred_all)


if __name__ == "__main__":
    main()
