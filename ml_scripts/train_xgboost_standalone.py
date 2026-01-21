import pandas as pd
import numpy as np
import xgboost as xgb
import joblib
import logging
import os
import sys
from pathlib import Path
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score, confusion_matrix, precision_score, recall_score, f1_score
from scipy.stats import uniform, randint

# Add parent directory to path to allow imports from ml_scripts
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml_scripts.data_loader import URLDataset

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def train_xgboost_pipeline(data_path, output_dir='models', n_iter=20, n_jobs=-1):
    """
    Trains an XGBoost model using RandomizedSearchCV for hyperparameter tuning.
    """
    logger.info("="*80)
    logger.info("XGBoost Training Pipeline with RandomizedSearchCV")
    logger.info("="*80)
    
    # 1. Load Data
    logger.info(f"Loading data from {data_path}...")
    dataset = URLDataset(data_path)
    dataset.load_data()
    
    # Check if features are already extracted (columns other than url, label, domain)
    non_feature_cols = ['url', 'label', 'domain', 'type']
    feature_cols = [col for col in dataset.raw_data.columns if col not in non_feature_cols]
    
    if feature_cols:
        logger.info(f"Using {len(feature_cols)} pre-extracted features.")
        dataset.feature_data = dataset.raw_data.copy()
        dataset.feature_columns = feature_cols
    else:
        logger.info("Extracting features (this might take a while)...")
        dataset.extract_features()
        
    # 2. Split Data
    # XGBoost handles scaling internally well, but scaling doesn't hurt. 
    # However, predictor.py does NOT scale features, so we must train on unscaled data 
    # to ensure consistency during inference.
    logger.info("Splitting data into train and test sets...")
    X_train, X_test, y_train, y_test = dataset.prepare_train_test_split(test_size=0.2, random_state=42, scale=False)
    
    # 3. Define Model
    # Use objective='binary:logistic' for binary classification
    # Use scale_pos_weight to handle class imbalance if necessary, 
    # but we'll include it in the search or calculate it.
    
    scale_pos_weight = 1
    # Check balance
    counts = y_train.value_counts()
    if 0 in counts and 1 in counts:
        scale_pos_weight = counts[0] / counts[1]
        logger.info(f"Calculated scale_pos_weight: {scale_pos_weight:.2f}")

    xgb_clf = xgb.XGBClassifier(
        objective='binary:logistic',
        eval_metric='logloss',
        random_state=42,
        n_jobs=1  # Parallelism handled by RandomizedSearchCV
    )

    # 4. Define Hyperparameter Search Space
    param_dist = {
        'n_estimators': randint(100, 1000),
        'max_depth': randint(3, 15),
        'learning_rate': uniform(0.01, 0.3),
        'subsample': uniform(0.6, 0.4),  # 0.6 to 1.0
        'colsample_bytree': uniform(0.6, 0.4), # 0.6 to 1.0
        'min_child_weight': randint(1, 7),
        'gamma': uniform(0, 0.5),
        'scale_pos_weight': [1, scale_pos_weight]
    }
    
    logger.info(f"Starting RandomizedSearchCV with {n_iter} iterations...")
    
    cv_strategy = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
    
    random_search = RandomizedSearchCV(
        estimator=xgb_clf,
        param_distributions=param_dist,
        n_iter=n_iter,
        scoring='f1',
        cv=cv_strategy,
        verbose=1,
        random_state=42,
        n_jobs=n_jobs
    )
    
    random_search.fit(X_train, y_train)
    
    # 5. Best Model and Evaluation
    best_model = random_search.best_estimator_
    best_params = random_search.best_params_
    
    logger.info("="*80)
    logger.info(f"Best Parameters: {best_params}")
    logger.info(f"Best CV F1 Score: {random_search.best_score_:.4f}")
    
    logger.info("Evaluating on Test Set...")
    y_pred = best_model.predict(X_test)
    y_prob = best_model.predict_proba(X_test)[:, 1]
    
    logger.info("\nClassification Report:")
    logger.info("\n" + classification_report(y_test, y_pred))
    
    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    
    logger.info(f"Accuracy: {acc:.4f}")
    logger.info(f"ROC AUC: {auc:.4f}")
    
    # 6. Save Model
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True, parents=True)
    
    model_file = output_path / "xgboost_model.pkl"

    # Important: Save as a dictionary structure compatible with MaliciousURLDetector.load_model
    from datetime import datetime
    model_data = {
        'model': best_model,
        'model_type': 'xgboost',
        'feature_names': dataset.feature_columns,
        'metrics': {
            'accuracy': acc,
            'auc': auc,
            'f1_score': f1_score(y_test, y_pred), # Compute actual F1 for consistency
            'best_params': best_params
        },
        'training_time': 'N/A', # not tracked in this script
        'timestamp': datetime.now().isoformat()
    }

    joblib.dump(model_data, model_file)
    logger.info(f"Model saved to {model_file}")
    
    return best_model, best_params

if __name__ == "__main__":
    # Default data path based on workspace info
    DEFAULT_DATA_PATH = "/workspace/IBD project/datasets/processed/url_features.csv"
    
    if len(sys.argv) > 1:
        data_file = sys.argv[1]
    elif os.path.exists(DEFAULT_DATA_PATH):
        data_file = DEFAULT_DATA_PATH
    else:
        logger.error(f"Data file not found at {DEFAULT_DATA_PATH}. Please provide a path.")
        sys.exit(1)
        
    train_xgboost_pipeline(data_file)
