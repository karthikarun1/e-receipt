import pytest
import requests

BASE_URL = 'http://127.0.0.1:5000'

def test_upload_model():
    with open('sample_model.pkl', 'rb') as f:
        response = requests.post(f'{BASE_URL}/upload_model', files={'model': f})
        assert response.status_code == 200
        assert response.json().get('message') == 'Model saved as models/sample_model.pkl'

def test_list_models():
    response = requests.get(f'{BASE_URL}/list_models')
    assert response.status_code == 200
    assert 'sample_model.pkl' in response.json().get('models')

def test_predict():
    data = [5.1, 3.5, 1.4, 0.2]
    response = requests.post(f'{BASE_URL}/predict', json={'model_filename': 'sample_model.pkl', 'data': data})
    assert response.status_code == 200
    assert 'prediction' in response.json()

def test_remove_model():
    response = requests.post(f'{BASE_URL}/remove_model', json={'model_filename': 'sample_model.pkl'})
    assert response.status_code == 200
    assert response.json().get('message') == 'Model sample_model.pkl removed successfully'

def test_edge_case():
    # Test with an invalid model filename
    response = requests.post(f'{BASE_URL}/predict', json={'model_filename': 'non_existent_model.pkl', 'data': [5.1, 3.5, 1.4, 0.2]})
    assert response.status_code == 404
    assert 'error' in response.json()
