import pickle
from sklearn.datasets import load_iris
from sklearn.ensemble import RandomForestClassifier

# Load the Iris dataset
iris = load_iris()
X, y = iris.data, iris.target

# Create and train a RandomForest model
model = RandomForestClassifier(n_estimators=10)
model.fit(X, y)

# Save the model to a file
with open('sample_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print('Model saved as sample_model.pkl')
