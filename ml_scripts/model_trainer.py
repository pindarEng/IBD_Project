
import pandas as pd
import numpy as np
import joblib
import json
import logging
from pathlib import Path
from datetime import datetime

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    accuracy_score,
    roc_auc_score
)
import xgboost as xgb

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MaliciousURLDetector:


    def __init__(self, model_type='random_forest', model_dir='models'):

        self.model_type = model_type
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True, parents=True)

        self.model = None
        self.feature_names = None
        self.metrics = {}
        self.training_time = None

    def create_model(self, **kwargs):

        if self.model_type == 'random_forest':
            default_params = {
                'n_estimators': 100,
                'max_depth': 20,
                'min_samples_split': 5,
                'min_samples_leaf': 2,
                'max_features': 'sqrt',
                'random_state': 42,
                'n_jobs': -1,
                'class_weight': 'balanced'
            }
            default_params.update(kwargs)
            self.model = RandomForestClassifier(**default_params)
            logger.info(f"Created Random Forest with params: {default_params}")

        elif self.model_type == 'xgboost':
            default_params = {
                'n_estimators': 100,
                'max_depth': 6,
                'learning_rate': 0.1,
                'subsample': 0.8,
                'colsample_bytree': 0.8,
                'random_state': 42,
                'n_jobs': -1,
                'scale_pos_weight': 1
            }
            default_params.update(kwargs)
            self.model = xgb.XGBClassifier(**default_params)
            logger.info(f"Created XGBoost with params: {default_params}")
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")

        return self.model

    def train(self, X_train, y_train, X_val=None, y_val=None):

        if self.model is None:
            self.create_model()

        logger.info(f"Training {self.model_type} model...")
        logger.info(f"Training samples: {len(X_train)}")

        start_time = datetime.now()

        if self.model_type == 'xgboost' and X_val is not None:
            eval_set = [(X_train, y_train), (X_val, y_val)]
            self.model.fit(
                X_train, y_train,
                eval_set=eval_set,
                verbose=False
            )
        else:
            self.model.fit(X_train, y_train)

        self.training_time = (datetime.now() - start_time).total_seconds()
        logger.info(f"Training completed in {self.training_time:.2f} seconds")

        if isinstance(X_train, pd.DataFrame):
            self.feature_names = X_train.columns.tolist()

        return self.model

    def evaluate(self, X_test, y_test, save_metrics=True):

        if self.model is None:
            raise ValueError("Model not trained. Call train() first")

        logger.info("Evaluating model...")

        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)[:, 1]

        self.metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1_score': f1_score(y_test, y_pred),
            'roc_auc': roc_auc_score(y_test, y_pred_proba),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'classification_report': classification_report(y_test, y_pred, output_dict=True)
        }

        logger.info(f"Accuracy: {self.metrics['accuracy']:.4f}")
        logger.info(f"Precision: {self.metrics['precision']:.4f}")
        logger.info(f"Recall: {self.metrics['recall']:.4f}")
        logger.info(f"F1-Score: {self.metrics['f1_score']:.4f}")
        logger.info(f"ROC-AUC: {self.metrics['roc_auc']:.4f}")

        logger.info("\nConfusion Matrix:")
        logger.info(f"{self.metrics['confusion_matrix']}")

        logger.info("\nClassification Report:")
        logger.info(classification_report(y_test, y_pred))

        if save_metrics:
            self._save_metrics()

        return self.metrics

    def hyperparameter_tuning(self, X_train, y_train, cv=5):

        logger.info(f"Starting hyperparameter tuning for {self.model_type}...")

        if self.model_type == 'random_forest':
            param_grid = {
                'n_estimators': [50, 100, 200],
                'max_depth': [10, 20, 30],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4],
                'max_features': ['sqrt', 'log2']
            }
            base_model = RandomForestClassifier(random_state=42, n_jobs=-1)

        elif self.model_type == 'xgboost':
            param_grid = {
                'n_estimators': [50, 100, 200],
                'max_depth': [3, 6, 9],
                'learning_rate': [0.01, 0.1, 0.3],
                'subsample': [0.6, 0.8, 1.0],
                'colsample_bytree': [0.6, 0.8, 1.0]
            }
            base_model = xgb.XGBClassifier(random_state=42, n_jobs=-1)
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")

        grid_search = GridSearchCV(
            base_model,
            param_grid,
            cv=cv,
            scoring='f1',
            n_jobs=-1,
            verbose=2
        )

        grid_search.fit(X_train, y_train)

        logger.info(f"Best parameters: {grid_search.best_params_}")
        logger.info(f"Best F1-score: {grid_search.best_score_:.4f}")

        self.model = grid_search.best_estimator_

        return grid_search.best_params_, grid_search.best_score_

    def get_feature_importance(self, top_n=20):

        if self.model is None:
            raise ValueError("Model not trained")

        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_

            if self.feature_names:
                feature_importance = pd.DataFrame({
                    'feature': self.feature_names,
                    'importance': importances
                }).sort_values('importance', ascending=False)
            else:
                feature_importance = pd.DataFrame({
                    'feature': [f'feature_{i}' for i in range(len(importances))],
                    'importance': importances
                }).sort_values('importance', ascending=False)

            logger.info(f"\nTop {top_n} Most Important Features:")
            logger.info(feature_importance.head(top_n).to_string())

            return feature_importance
        else:
            logger.warning("Model does not support feature importance")
            return None

    def predict(self, X):

        if self.model is None:
            raise ValueError("Model not trained or loaded")

        return self.model.predict(X)

    def predict_proba(self, X):

        if self.model is None:
            raise ValueError("Model not trained or loaded")

        return self.model.predict_proba(X)

    def save_model(self, filename=None):

        if self.model is None:
            raise ValueError("No model to save")

        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.model_type}_{timestamp}.pkl"

        model_path = self.model_dir / filename

        model_data = {
            'model': self.model,
            'model_type': self.model_type,
            'feature_names': self.feature_names,
            'metrics': self.metrics,
            'training_time': self.training_time,
            'timestamp': datetime.now().isoformat()
        }

        joblib.dump(model_data, model_path)
        logger.info(f"Model saved to {model_path}")

        return model_path

    def load_model(self, model_path):

        logger.info(f"Loading model from {model_path}")

        model_data = joblib.load(model_path)

        self.model = model_data['model']
        self.model_type = model_data['model_type']
        self.feature_names = model_data.get('feature_names')
        self.metrics = model_data.get('metrics', {})
        self.training_time = model_data.get('training_time')

        logger.info(f"Loaded {self.model_type} model")
        if self.metrics:
            logger.info(f"Model F1-score: {self.metrics.get('f1_score', 'N/A')}")

        return self.model

    def _save_metrics(self):

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        metrics_file = self.model_dir / f"{self.model_type}_metrics_{timestamp}.json"

        metrics_copy = self.metrics.copy()
        for key, value in metrics_copy.items():
            if isinstance(value, (np.integer, np.floating)):
                metrics_copy[key] = float(value)

        with open(metrics_file, 'w') as f:
            json.dump(metrics_copy, f, indent=2)

        logger.info(f"Metrics saved to {metrics_file}")

if __name__ == "__main__":
    logger.info("Model trainer module loaded successfully")
