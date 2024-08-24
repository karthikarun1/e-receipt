import unittest
from app import app

class PredictEndpointTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_predict_success(self):
        response = self.app.post('/predict',
                                 json={
                                     "version": "v2",
                                     "model_filename": "sample_model.pkl",
                                     "data": [5.9, 3.0, 4.2, 1.5],
                                       },
                                 auth=('admin', 'secret'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('prediction', response.json)

    def test_predict_authentication_failure(self):
        response = self.app.post('/predict',
                                 json={"data": [5.9, 3.0, 4.2, 1.5]},
                                 auth=('wrong_user', 'wrong_password'))
        self.assertEqual(response.status_code, 401)
        self.assertIn('Authentication required', response.json['message'])

    def test_predict_invalid_data(self):
        response = self.app.post('/predict',
                                 json={"data": "invalid_data"},
                                 auth=('admin', 'secret'))
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.json)

if __name__ == '__main__':
    unittest.main()
