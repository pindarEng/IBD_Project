import pandas as pd
import sys
import os
import logging

# Add the parent directory to sys.path to resolve helper_functions
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from helper_functions.features_extractor import perform_lexical_analysis_on_df

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    input_file = 'datasets/processed/processed_urls.csv'
    output_file = 'datasets/processed/url_features.csv'

    logger.info(f"Loading data from {input_file}...")
    try:
        df = pd.read_csv(input_file)
        logger.info(f"Loaded {len(df)} rows.")
    except FileNotFoundError:
        logger.error(f"File not found: {input_file}")
        return

    logger.info("Starting feature extraction...")
    # Ensure there is a 'url' column
    if 'url' not in df.columns:
        logger.error("Input CSV must have a 'url' column.")
        return

    # Process in batches if necessary, but for ~700k rows pandas apply might be fine if memory allows.
    # perform_lexical_analysis_on_df uses apply().
    
    start_time = pd.Timestamp.now()
    df_features = perform_lexical_analysis_on_df(df)
    end_time = pd.Timestamp.now()
    
    logger.info(f"Feature extraction completed in {(end_time - start_time).total_seconds():.2f} seconds.")
    
    logger.info(f"Saving features to {output_file}...")
    df_features.to_csv(output_file, index=False)
    logger.info("Done.")

if __name__ == "__main__":
    main()
