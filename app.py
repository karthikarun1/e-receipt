from flask import Flask, request, jsonify
import pickle
import os

app = Flask(__name__)
model_directory = 'models'  # Directory where models will be stored

def load_model_from_file(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)

@app.route('/upload_model', methods=['POST'])
def upload_model():
    model_file = request.files.get('model')
    if not model_file:
        return jsonify({'error': 'No model file provided'}), 400

    filename = os.path.join(model_directory, model_file.filename)
    model_file.save(filename)
    return jsonify({'message': f'Model saved as {filename}'}), 200

@app.route('/health_check', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok'}), 200

@app.route('/list_models', methods=['GET'])
def list_models():
    if not os.path.exists(model_directory):
        os.makedirs(model_directory)
    models = os.listdir(model_directory)
    return jsonify({'models': models}), 200

@app.route('/remove_model', methods=['POST'])
def remove_model():
    model_filename = request.json.get('model_filename')
    if not model_filename:
        return jsonify({'error': 'No model filename provided'}), 400

    file_path = os.path.join(model_directory, model_filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return jsonify({'message': f'Model {model_filename} removed successfully'}), 200
    else:
        return jsonify({'error': 'Model file not found'}), 404

@app.route('/predict', methods=['POST'])
def predict():
    model_filename = request.json.get('model_filename')
    if not model_filename:
        return jsonify({'error': 'No model filename provided'}), 400

    model_path = os.path.join(model_directory, model_filename)
    if not os.path.exists(model_path):
        return jsonify({'error': 'Model file not found'}), 404

    model = load_model_from_file(model_path)
    data = request.json.get('data')
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        prediction = model.predict([data])
        return jsonify({'prediction': prediction.tolist()}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
