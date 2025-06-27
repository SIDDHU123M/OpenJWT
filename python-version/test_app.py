import pytest
import json
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def test_user():
    return {
        'email': 'test@example.com',
        'password': 'test123',
        'name': 'Test User'
    }

class TestOpenJWTAPI:
    def test_documentation_endpoint(self, client):
        """Test the documentation endpoint."""
        response = client.get('/')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'service' in data
        assert 'OpenJWT' in data['service']
        assert 'endpoints' in data

    def test_health_check(self, client):
        """Test the health check endpoint."""
        response = client.get('/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert 'timestamp' in data

    def test_register_user(self, client, test_user):
        """Test user registration."""
        response = client.post('/register',
                             data=json.dumps(test_user),
                             content_type='application/json')
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['success'] is True
        assert 'token' in data
        assert data['user']['email'] == test_user['email']
        assert data['user']['name'] == test_user['name']
        assert 'password' not in data['user']
        return data['token']

    def test_register_duplicate_user(self, client, test_user):
        """Test registration with existing email."""
        # Register first user
        client.post('/register',
                   data=json.dumps(test_user),
                   content_type='application/json')
        
        # Try to register again
        response = client.post('/register',
                             data=json.dumps(test_user),
                             content_type='application/json')
        assert response.status_code == 409
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'already exists' in data['message']

    def test_register_invalid_email(self, client, test_user):
        """Test registration with invalid email."""
        invalid_user = test_user.copy()
        invalid_user['email'] = 'invalid-email'
        
        response = client.post('/register',
                             data=json.dumps(invalid_user),
                             content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] is False

    def test_register_short_password(self, client, test_user):
        """Test registration with short password."""
        invalid_user = test_user.copy()
        invalid_user['password'] = '123'
        invalid_user['email'] = 'test2@example.com'
        
        response = client.post('/register',
                             data=json.dumps(invalid_user),
                             content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] is False

    def test_register_missing_name(self, client):
        """Test registration without name."""
        user_data = {
            'email': 'test3@example.com',
            'password': 'test123'
        }
        
        response = client.post('/register',
                             data=json.dumps(user_data),
                             content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] is False

    def test_login_valid_credentials(self, client, test_user):
        """Test login with valid credentials."""
        # Register user first
        client.post('/register',
                   data=json.dumps(test_user),
                   content_type='application/json')
        
        # Login
        login_data = {
            'email': test_user['email'],
            'password': test_user['password']
        }
        response = client.post('/login',
                             data=json.dumps(login_data),
                             content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert 'token' in data
        assert data['user']['email'] == test_user['email']

    def test_login_invalid_email(self, client):
        """Test login with non-existent email."""
        login_data = {
            'email': 'nonexistent@example.com',
            'password': 'test123'
        }
        response = client.post('/login',
                             data=json.dumps(login_data),
                             content_type='application/json')
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'Invalid email or password' in data['message']

    def test_login_invalid_password(self, client, test_user):
        """Test login with wrong password."""
        # Register user first
        client.post('/register',
                   data=json.dumps(test_user),
                   content_type='application/json')
        
        # Try login with wrong password
        login_data = {
            'email': test_user['email'],
            'password': 'wrongpassword'
        }
        response = client.post('/login',
                             data=json.dumps(login_data),
                             content_type='application/json')
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'Invalid email or password' in data['message']

    def test_verify_valid_token(self, client, test_user):
        """Test token verification with valid token."""
        # Register user and get token
        response = client.post('/register',
                             data=json.dumps(test_user),
                             content_type='application/json')
        token = json.loads(response.data)['token']
        
        # Verify token
        verify_data = {'token': token}
        response = client.post('/verify',
                             data=json.dumps(verify_data),
                             content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['user']['email'] == test_user['email']

    def test_verify_invalid_token(self, client):
        """Test token verification with invalid token."""
        verify_data = {'token': 'invalid-token'}
        response = client.post('/verify',
                             data=json.dumps(verify_data),
                             content_type='application/json')
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'Invalid or expired token' in data['message']

    def test_verify_empty_token(self, client):
        """Test token verification with empty token."""
        verify_data = {'token': ''}
        response = client.post('/verify',
                             data=json.dumps(verify_data),
                             content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] is False

    def test_404_handler(self, client):
        """Test 404 error handling."""
        response = client.get('/unknown-endpoint')
        assert response.status_code == 404
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'available_endpoints' in data

    def test_invalid_json(self, client):
        """Test handling of invalid JSON."""
        response = client.post('/register',
                             data='invalid json',
                             content_type='application/json')
        assert response.status_code == 400
