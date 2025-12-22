import csv
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, accuracy_score

csv_path = "results/xss_results_20251219_144241.csv"

y_true, y_pred = [], []
with open(csv_path, newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        gt = row["GroundTruth"].strip()
        pr = row["Predicted"].strip()
        y_true.append(gt)
        y_pred.append(pr)

labels = ["VULNERABLE", "SAFE"]

cm = confusion_matrix(y_true, y_pred, labels=labels)
print("Confusion matrix (rows=true, cols=pred):")
print(cm)

# Karena ini binary dengan label eksplisit:
accuracy = accuracy_score(y_true, y_pred)
precision = precision_score(y_true, y_pred, pos_label="VULNERABLE", zero_division=0)
recall = recall_score(y_true, y_pred, pos_label="VULNERABLE", zero_division=0)
f1 = f1_score(y_true, y_pred, pos_label="VULNERABLE", zero_division=0)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1-score : {f1:.4f}")
