import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# --- CONFIGURATION ---
# Make sure this matches the name of the file you downloaded
CSV_FILE_PATH = r"D:\Downloads\DataSets\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
MODEL_FILE = 'rf_model.pkl'

def train_brain():
    print(f"Loading dataset: {CSV_FILE_PATH}...")
    
    if not os.path.exists(CSV_FILE_PATH):
        print("ERROR: CSV file not found! Please download the dataset and place it in this folder.")
        return

    # 1. Load Data
    # We only load a sample (50,000 rows) to make training fast for this demo. 
    # Remove 'nrows=50000' to train on the full dataset (takes longer).
    df = pd.read_csv(CSV_FILE_PATH, nrows=50000)
    
    # 2. Clean Data
    # Strip whitespace from column names
    df.columns = df.columns.str.strip()
    
    print("Columns in dataset:", df.columns.tolist())
    
    # Drop rows with missing or infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # 3. Prepare Features (X) and Labels (y)
    # The 'Label' column tells us if it is BENIGN or ATTACK
    y = df['Label']
    X = df.drop(['Label', 'Destination Port'], axis=1) # Drop Label and Port (Port can be misleading)

    # Encode Labels (Benign -> 0, DDoS -> 1)
    le = LabelEncoder()
    y = le.fit_transform(y)
    
    # Save the label mapping for later
    print(f"Labels encoded: {dict(zip(le.classes_, le.transform(le.classes_)))}")

    # 4. Split Data (80% for training, 20% for testing)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 5. Train the Model (Random Forest)
    print("Training Random Forest Model (this might take a minute)...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)

    # 6. Evaluate
    score = rf.score(X_test, y_test)
    print(f"Model Training Complete! Accuracy: {score * 100:.2f}%")

    # 7. Save the Brain
    joblib.dump(rf, MODEL_FILE)
    print(f"Model saved to {MODEL_FILE}")
    
    # We also need to save the list of features so our app knows what to look for later
    joblib.dump(X.columns.tolist(), 'model_features.pkl')
    print("Feature list saved to model_features.pkl")

if __name__ == "__main__":
    train_brain()