import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import logging
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from helper_functions.features_extractor import perform_lexical_analysis

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class URLDataset:
    def __init__(self, data_path=None):

        self.data_path = data_path
        self.raw_data = None
        self.feature_data = None
        self.feature_columns = None
        self.scaler = StandardScaler()

    def load_data(self, data_path=None):

        if data_path:
            self.data_path = data_path

        if not self.data_path:
            raise ValueError("No data path provided")

        logger.info(f"Loading data from {self.data_path}")
        self.raw_data = pd.read_csv(self.data_path)

        if 'url' not in self.raw_data.columns:
            raise ValueError("Dataset must contain 'url' column")

        if 'label' not in self.raw_data.columns and 'type' in self.raw_data.columns:
            self.raw_data = self.raw_data.rename(columns={'type': 'label'})

        if 'label' not in self.raw_data.columns:
            raise ValueError("Dataset must contain 'label' or 'type' column")

        self.raw_data['label'] = self.raw_data['label'].apply(self._normalize_label)
        before = len(self.raw_data)
        self.raw_data = self.raw_data.dropna(subset=['label'])
        after = len(self.raw_data)
        dropped = before - after
        if dropped > 0:
            logger.warning(f"Dropped {dropped} rows with unknown labels during normalization")

        logger.info(f"Loaded {len(self.raw_data)} URLs")
        logger.info(f"Class distribution:\n{self.raw_data['label'].value_counts()}")

        return self.raw_data

    def extract_features(self, df=None):

        if df is None:
            if self.raw_data is None:
                raise ValueError("No data loaded. Call load_data() first")
            df = self.raw_data

        logger.info("Extracting features from URLs...")

        feature_dfs = []
        for idx, row in df.iterrows():
            if idx % 1000 == 0:
                logger.info(f"Processing URL {idx}/{len(df)}")

            try:
                features = perform_lexical_analysis(row['url'])
                if 'label' in row:
                    features['label'] = row['label']
                feature_dfs.append(features)
            except Exception as e:
                logger.error(f"Error processing URL {row['url']}: {e}")
                continue

        self.feature_data = pd.concat(feature_dfs, ignore_index=True)

        exclude_cols = ['url', 'domain', 'label']
        self.feature_columns = [col for col in self.feature_data.columns
                               if col not in exclude_cols]

        logger.info(f"Extracted {len(self.feature_columns)} features")
        logger.info(f"Features: {self.feature_columns}")

        return self.feature_data

    def prepare_train_test_split(self, test_size=0.2, random_state=42, scale=True):

        if self.feature_data is None:
            raise ValueError("No features extracted. Call extract_features() first")

        if 'label' not in self.feature_data.columns:
            raise ValueError("Dataset must contain 'label' column")

        X = self.feature_data[self.feature_columns]
        y = self.feature_data['label']

        X = X.fillna(0)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )

        logger.info(f"Train set: {len(X_train)} samples")
        logger.info(f"Test set: {len(X_test)} samples")
        logger.info(f"Train labels: {y_train.value_counts().to_dict()}")
        logger.info(f"Test labels: {y_test.value_counts().to_dict()}")

        if scale:
            logger.info("Applying standard scaling to features")
            X_train = self.scaler.fit_transform(X_train)
            X_test = self.scaler.transform(X_test)

            X_train = pd.DataFrame(X_train, columns=self.feature_columns)
            X_test = pd.DataFrame(X_test, columns=self.feature_columns)

        return X_train, X_test, y_train, y_test

    def load_from_multiple_sources(self, url_list, labels):

        self.raw_data = pd.DataFrame({
            'url': url_list,
            'label': labels
        })

        logger.info(f"Created dataset with {len(self.raw_data)} URLs")
        return self.raw_data

    @staticmethod
    def _normalize_label(value):

        if pd.isna(value):
            return np.nan

        if isinstance(value, str):
            v = value.strip().lower()
        else:
            v = value

        malicious_values = {1, '1', 'bad', 'malicious', 'phishing', 'defacement'}
        benign_values = {0, '0', 'benign', 'good', 'legit', 'safe', 'normal', 'clean'}

        if v in malicious_values:
            return 1
        if v in benign_values:
            return 0

        return np.nan

    def save_features(self, output_path):

        if self.feature_data is None:
            raise ValueError("No features to save")

        self.feature_data.to_csv(output_path, index=False)
        logger.info(f"Saved features to {output_path}")

    def get_feature_importance_data(self):

        if self.feature_data is None:
            raise ValueError("No features extracted")

        return {
            'features': self.feature_columns,
            'data': self.feature_data[self.feature_columns + ['label']]
        }
