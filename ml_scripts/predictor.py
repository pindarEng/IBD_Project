
import sys
import os
import logging
import pandas as pd
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from helper_functions.features_extractor import perform_lexical_analysis
from ml_scripts.model_trainer import MaliciousURLDetector

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class URLPredictor:


    def __init__(self, lightweight_model_path=None, deep_model_path=None):

        self.lightweight_model = None
        self.deep_model = None
        self.feature_names = None

        if lightweight_model_path:
            self.load_lightweight_model(lightweight_model_path)

        if deep_model_path:
            self.load_deep_model(deep_model_path)

    def load_lightweight_model(self, model_path):

        logger.info(f"Loading lightweight model from {model_path}")
        self.lightweight_model = MaliciousURLDetector()
        self.lightweight_model.load_model(model_path)
        self.feature_names = self.lightweight_model.feature_names
        logger.info("Lightweight model loaded successfully")

    def load_deep_model(self, model_path):

        logger.info(f"Loading deep model from {model_path}")
        self.deep_model = MaliciousURLDetector()
        self.deep_model.load_model(model_path)
        logger.info("Deep model loaded successfully")

    def predict_single_url(self, url, return_confidence=True):

        if self.lightweight_model is None:
            raise ValueError("No model loaded. Load a model first.")

        features_df = perform_lexical_analysis(url)

        X = self._prepare_features(features_df)

        prediction = self.lightweight_model.predict(X)[0]

        result = {
            'url': url,
            'prediction': int(prediction),
            'label': 'malicious' if prediction == 1 else 'benign'
        }

        if return_confidence:
            proba = self.lightweight_model.predict_proba(X)[0]
            result['confidence'] = float(proba[int(prediction)])
            result['malicious_probability'] = float(proba[1])
            result['benign_probability'] = float(proba[0])

        return result

    def predict_batch(self, urls, batch_size=100):

        if self.lightweight_model is None:
            raise ValueError("No model loaded. Load a model first.")

        logger.info(f"Processing {len(urls)} URLs in batches of {batch_size}")

        results = []
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i+batch_size]
            logger.info(f"Processing batch {i//batch_size + 1}/{(len(urls)-1)//batch_size + 1}")

            for url in batch:
                try:
                    result = self.predict_single_url(url)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error processing URL {url}: {e}")
                    results.append({
                        'url': url,
                        'prediction': -1,
                        'label': 'error',
                        'error': str(e)
                    })

        return results

    def predict_tiered(self, url, threshold=0.7):

        result = self.predict_single_url(url, return_confidence=True)
        result['tier'] = 'lightweight'

        if result['confidence'] < threshold and self.deep_model is not None:
            logger.info(f"Low confidence ({result['confidence']:.2f}), using deep model")

            features_df = perform_lexical_analysis(url)
            X = self._prepare_features(features_df)

            deep_prediction = self.deep_model.predict(X)[0]
            deep_proba = self.deep_model.predict_proba(X)[0]

            result['tier'] = 'deep'
            result['prediction'] = int(deep_prediction)
            result['label'] = 'malicious' if deep_prediction == 1 else 'benign'
            result['confidence'] = float(deep_proba[int(deep_prediction)])
            result['malicious_probability'] = float(deep_proba[1])
            result['benign_probability'] = float(deep_proba[0])

        return result

    def _prepare_features(self, features_df):

        if self.feature_names:
            exclude_cols = ['url', 'domain', 'label']
            available_features = [col for col in features_df.columns
                                 if col not in exclude_cols]

            for feature in self.feature_names:
                if feature not in available_features:
                    features_df[feature] = 0

            X = features_df[self.feature_names]
        else:
            exclude_cols = ['url', 'domain', 'label']
            feature_cols = [col for col in features_df.columns
                           if col not in exclude_cols]
            X = features_df[feature_cols]

        X = X.fillna(0)

        return X

    def get_model_info(self):

        info = {}

        if self.lightweight_model:
            info['lightweight_model'] = {
                'type': self.lightweight_model.model_type,
                'metrics': self.lightweight_model.metrics,
                'feature_count': len(self.feature_names) if self.feature_names else None
            }

        if self.deep_model:
            info['deep_model'] = {
                'type': self.deep_model.model_type,
                'metrics': self.deep_model.metrics
            }

        return info
