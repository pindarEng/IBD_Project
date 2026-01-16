import sys
import os
import argparse
import logging
import shutil
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml_scripts.data_loader import URLDataset
from ml_scripts.model_trainer import MaliciousURLDetector

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def train_model(data_path, model_type='random_forest', tune_hyperparameters=False,
                test_size=0.2, output_dir='models'):
    logger.info("="*80)
    logger.info("MALICIOUS URL DETECTION - MODEL TRAINING PIPELINE")
    logger.info("="*80)
    logger.info(f"Model Type: {model_type.upper()}")
    logger.info(f"Data Source: {data_path}")
    logger.info("="*80)

    logger.info("\n[STEP 1/5] Loading dataset...")
    dataset = URLDataset(data_path)
    dataset.load_data()

    non_feature_cols = ['url', 'label', 'domain']
    feature_cols = [col for col in dataset.raw_data.columns if col not in non_feature_cols]

    features_path = None
    if len(feature_cols) > 0:
        logger.info(f"\n[STEP 2/5] Features already extracted ({len(feature_cols)} features found)")
        logger.info("Skipping feature extraction step...")

        dataset.feature_data = dataset.raw_data.copy()
        dataset.feature_columns = feature_cols
    else:
        logger.info("\n[STEP 2/5] Extracting lexical and statistical features...")
        dataset.extract_features()

        features_path = Path(output_dir) / 'extracted_features.csv'
        features_path.parent.mkdir(exist_ok=True, parents=True)
        dataset.save_features(features_path)

    logger.info("\n[STEP 3/5] Preparing train/test split...")
    X_train, X_test, y_train, y_test = dataset.prepare_train_test_split(
        test_size=test_size,
        scale=True
    )

    logger.info(f"\n[STEP 4/5] Training {model_type} model...")
    detector = MaliciousURLDetector(model_type=model_type, model_dir=output_dir)

    if tune_hyperparameters:
        logger.info("Performing hyperparameter tuning (this may take a while)...")
        best_params, best_score = detector.hyperparameter_tuning(X_train, y_train, cv=5)
        logger.info(f"Best hyperparameters: {best_params}")
        logger.info(f"Best cross-validation F1-score: {best_score:.4f}")
    else:
        detector.create_model()
        detector.train(X_train, y_train)

    logger.info("\n[STEP 5/5] Evaluating model performance...")
    metrics = detector.evaluate(X_test, y_test)

    logger.info("\n" + "="*80)
    logger.info("SAVING MODEL")
    logger.info("="*80)
    model_path = detector.save_model()

    canonical_name = 'random_forest_model.pkl' if model_type == 'random_forest' else 'xgboost_model.pkl'
    canonical_path = Path(output_dir) / canonical_name
    try:
        shutil.copy(model_path, canonical_path)
        logger.info(f"Canonical model copy saved to: {canonical_path}")
    except Exception as copy_err:
        logger.warning(f"Could not save canonical model copy: {copy_err}")

    logger.info("\n" + "="*80)
    logger.info("TRAINING COMPLETE - SUMMARY")
    logger.info("="*80)
    logger.info(f"Model Type: {model_type}")
    logger.info(f"Training Time: {detector.training_time:.2f} seconds")
    logger.info(f"Test Accuracy: {metrics['accuracy']:.4f}")
    logger.info(f"Test Precision: {metrics['precision']:.4f}")
    logger.info(f"Test Recall: {metrics['recall']:.4f}")
    logger.info(f"Test F1-Score: {metrics['f1_score']:.4f}")
    logger.info(f"ROC-AUC Score: {metrics['roc_auc']:.4f}")
    logger.info(f"Model saved to: {model_path}")
    if features_path:
        logger.info(f"Features saved to: {features_path}")
    logger.info("="*80)

    return detector, metrics

def train_both_models(data_path, output_dir='models', tune_hyperparameters=False):
    logger.info("\n" + "#"*80)
    logger.info("TRAINING BOTH ENSEMBLE MODELS FOR COMPARISON")
    logger.info("#"*80 + "\n")

    results = {}

    logger.info("\n>>> TRAINING RANDOM FOREST <<<\n")
    rf_detector, rf_metrics = train_model(
        data_path,
        model_type='random_forest',
        tune_hyperparameters=tune_hyperparameters,
        output_dir=output_dir
    )
    results['random_forest'] = {'detector': rf_detector, 'metrics': rf_metrics}

    logger.info("\n>>> TRAINING XGBOOST <<<\n")
    xgb_detector, xgb_metrics = train_model(
        data_path,
        model_type='xgboost',
        tune_hyperparameters=tune_hyperparameters,
        output_dir=output_dir
    )
    results['xgboost'] = {'detector': xgb_detector, 'metrics': xgb_metrics}

    logger.info("\n" + "="*80)
    logger.info("MODEL COMPARISON")
    logger.info("="*80)
    logger.info(f"{'Metric':<20} {'Random Forest':<20} {'XGBoost':<20}")
    logger.info("-"*80)

    metrics_to_compare = ['accuracy', 'precision', 'recall', 'f1_score', 'roc_auc']
    for metric in metrics_to_compare:
        rf_val = rf_metrics[metric]
        xgb_val = xgb_metrics[metric]
        logger.info(f"{metric.upper():<20} {rf_val:<20.4f} {xgb_val:<20.4f}")

    best_model = 'random_forest' if rf_metrics['f1_score'] > xgb_metrics['f1_score'] else 'xgboost'
    logger.info("="*80)
    logger.info(f"BEST MODEL (by F1-score): {best_model.upper()}")
    logger.info("="*80)

    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Train malicious URL detection models'
    )
    parser.add_argument(
        '--data',
        type=str,
        help='Path to CSV file with URL data (columns: url, label)'
    )
    parser.add_argument(
        '--model',
        type=str,
        choices=['random_forest', 'xgboost', 'both'],
        default='both',
        help='Model type to train'
    )
    parser.add_argument(
        '--tune',
        action='store_true',
        help='Perform hyperparameter tuning'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='models',
        help='Output directory for models'
    )

    args = parser.parse_args()

    try:
        if args.data:
            if args.model == 'both':
                train_both_models(
                    args.data,
                    output_dir=args.output,
                    tune_hyperparameters=args.tune
                )
            else:
                train_model(
                    args.data,
                    model_type=args.model,
                    tune_hyperparameters=args.tune,
                    output_dir=args.output
                )
        else:
            logger.error("Please provide --data path")
            parser.print_help()
    except Exception as e:
        logger.error(f"Training failed: {e}", exc_info=True)
        sys.exit(1)
