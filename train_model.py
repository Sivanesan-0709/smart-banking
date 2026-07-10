import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score, accuracy_score
import joblib
import json
import os

def generate_synthetic_data(n_samples=25000, fraud_ratio=0.08):
    np.random.seed(42)
    
    n_fraud = int(n_samples * fraud_ratio)
    n_normal = n_samples - n_fraud
    
    # 1. Generate Normal Transactions
    normal_types = np.random.choice(['CASH_OUT', 'TRANSFER'], size=n_normal)
    normal_amounts = np.random.exponential(scale=20000, size=n_normal) + 10
    normal_old_orig = normal_amounts + np.random.exponential(scale=50000, size=n_normal)
    normal_new_orig = normal_old_orig - normal_amounts
    
    normal_old_dest = np.random.exponential(scale=100000, size=n_normal)
    normal_new_dest = normal_old_dest + normal_amounts
    
    df_normal = pd.DataFrame({
        'type': normal_types,
        'amount': normal_amounts,
        'oldbalanceOrig': normal_old_orig,
        'newbalanceOrig': normal_new_orig,
        'oldbalanceDest': normal_old_dest,
        'newbalanceDest': normal_new_dest,
        'isFraud': 0
    })
    
    # 2. Generate Fraudulent Transactions (Patterns from PaySim)
    # Fraud pattern A: Emptying the account (newbalanceOrig = 0)
    fraud_types = np.random.choice(['CASH_OUT', 'TRANSFER'], size=n_fraud)
    fraud_old_orig = np.random.exponential(scale=150000, size=n_fraud) + 5000
    fraud_amounts = fraud_old_orig.copy() # empty account
    fraud_new_orig = np.zeros(n_fraud)
    
    # In fraud, destination balances often start at 0 and either stay 0 (instant cashout) or receive funds
    fraud_old_dest = np.random.choice([0.0, 5000.0], size=n_fraud, p=[0.9, 0.1])
    fraud_new_dest = np.random.choice([0.0, 1.0], size=n_fraud, p=[0.8, 0.2]) * fraud_amounts
    
    # Fraud pattern B: Huge random transfers that exceed normal amounts
    heavy_fraud_idx = np.random.choice(range(n_fraud), size=int(n_fraud * 0.3), replace=False)
    for idx in heavy_fraud_idx:
        fraud_amounts[idx] = np.random.uniform(200000, 1000000)
        fraud_old_orig[idx] = fraud_amounts[idx] + np.random.uniform(0, 10000)
        fraud_new_orig[idx] = fraud_old_orig[idx] - fraud_amounts[idx]
        
    df_fraud = pd.DataFrame({
        'type': fraud_types,
        'amount': fraud_amounts,
        'oldbalanceOrig': fraud_old_orig,
        'newbalanceOrig': fraud_new_orig,
        'oldbalanceDest': fraud_old_dest,
        'newbalanceDest': fraud_new_dest,
        'isFraud': 1
    })
    
    df = pd.concat([df_normal, df_fraud], ignore_index=True)
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df

def train_and_save():
    print("Generating high-quality synthetic transaction data...")
    df = generate_synthetic_data()
    
    X = df.drop('isFraud', axis=1)
    y = df['isFraud']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("Building preprocessing pipeline...")
    # Define preprocessing
    numeric_features = ['amount', 'oldbalanceOrig', 'newbalanceOrig', 'oldbalanceDest', 'newbalanceDest']
    categorical_features = ['type']
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numeric_features),
            ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
        ]
    )
    
    # Define complete pipeline with estimator
    pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(n_estimators=100, random_state=42, max_depth=12, class_weight='balanced'))
    ])
    
    print("Training Random Forest Classifier on synthetic PaySim-like dataset...")
    pipeline.fit(X_train, y_train)
    
    # Evaluate model
    y_pred = pipeline.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred).tolist()
    
    print("\n--- Model Evaluation Results ---")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print("Confusion Matrix:\n", np.array(cm))
    
    # Save model pipeline
    model_path = r"c:\Users\User\OneDrive\Desktop\Smart Banking and Fraud Detection System\banking_app_rf.pkl"
    joblib.dump(pipeline, model_path)
    print(f"\nTrained model pipeline saved successfully to {model_path}")
    
    # Export metrics for UI consumption
    metrics = {
        "status": "active",
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": cm,
        "n_samples": len(df),
        "fraud_percentage": round((df['isFraud'].sum() / len(df)) * 100, 2)
    }
    
    metrics_path = r"c:\Users\User\OneDrive\Desktop\Smart Banking and Fraud Detection System\model_metrics.json"
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=4)
    print(f"Model metrics saved to {metrics_path}")

if __name__ == '__main__':
    train_and_save()
