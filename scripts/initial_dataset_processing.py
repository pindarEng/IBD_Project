import pandas as pd
import os

def load_and_process_data():    
    # 1. Load data.csv
    # Schema: url, label (good/bad)
    df_data = pd.read_csv('datasets/raw/data.csv')
    df_data['label'] = df_data['label'].map({'good': 0, 'bad': 1})
    print(f"Loaded data.csv: {df_data.shape}")

    # 2. Load malicious_phish.csv
    # Schema: url, type (benign, defacement, phishing, malware)
    df_phish = pd.read_csv('datasets/raw/malicious_phish.csv')
    df_phish['label'] = df_phish['type'].map({
        'benign': 0, 
        'defacement': 1, 
        'phishing': 1, 
        'malware': 1
    })
    df_phish = df_phish[['url', 'label']]
    print(f"Loaded malicious_phish.csv: {df_phish.shape}")

    # 3. Load cleaned_topreal_urls.csv
    # Schema: benign urls only
    df_top = pd.read_csv('datasets/raw/cleaned_topreal_urls.csv')
    df_top['label'] = 0
    print(f"Loaded cleaned_topreal_urls.csv: {df_top.shape}")

    # Combine all
    print("combining datasets")
    combined_df = pd.concat([df_data, df_phish, df_top], ignore_index=True)
    
    # Normalization (per PDF requirements)
    print("Normalizing URLs - lowercasing")
    combined_df['url'] = combined_df['url'].astype(str).str.lower()
    # combined_df['url'] = combined_df['url'].str.replace(r'^https?://', '', regex=True)
    # combined_df['url'] = combined_df['url'].str.replace(r'^www\.', '', regex=True)
    
    # Remove duplicates
    print("Removing duplicates...")
    initial_count = len(combined_df)
    combined_df.drop_duplicates(subset=['url'], inplace=True)
    final_count = len(combined_df)
    print(f"Removed {initial_count - final_count} duplicates.")
    
    # Basic validation
    print("Checking for nulls...")
    combined_df.dropna(subset=['url'], inplace=True)
    
    # shuffle
    combined_df = combined_df.sample(frac=1).reset_index(drop=True)
    
    # Save/workspace/IBD project/datasets/processed
    output_path = 'datasets/processed/processed_urls.csv'
    combined_df.to_csv(output_path, index=False)
    print(f"Saved processed data to {output_path} with {len(combined_df)} rows.")
    print(combined_df['label'].value_counts())

if __name__ == "__main__":
    load_and_process_data()
