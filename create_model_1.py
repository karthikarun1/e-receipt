import numpy as np
from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
import joblib

# Generate a synthetic dataset with fewer classes and clusters
X, y = make_classification(n_samples=500, n_features=10, n_classes=2, n_clusters_per_class=1, random_state=42)

# Train a RandomForestClassifier
model = RandomForestClassifier(n_estimators=50, random_state=42)
model.fit(X, y)

# Save the model to a file
joblib.dump(model, 'random_forest_model.pkl')

print("Model training complete and saved as 'random_forest_model.pkl'")
