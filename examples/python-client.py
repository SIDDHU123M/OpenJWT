#!/usr/bin/env python3

"""
OpenJWT Usage Examples

This script demonstrates how to use the OpenJWT service
in a Python application.
"""

import json
import requests
from typing import Dict, Any, Optional

# Replace with your OpenJWT service URL
API_BASE_URL = 'http://localhost:5000'

class OpenJWTClient:
    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json'})
    
    def _make_request(self, endpoint: str, method: str = 'GET', data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make HTTP request to the API."""
        try:
            url = f"{self.base_url}{endpoint}"
            
            if method.upper() == 'POST':
                response = self.session.post(url, json=data)
            else:
                response = self.session.get(url)
            
            return {
                'success': response.ok,
                'status': response.status_code,
                'data': response.json()
            }
        except requests.RequestException as e:
            return {
                'success': False,
                'error': str(e)
            }
        except json.JSONDecodeError:
            return {
                'success': False,
                'error': 'Invalid JSON response'
            }
    
    def register(self, email: str, password: str, name: str) -> Dict[str, Any]:
        """Register a new user."""
        return self._make_request('/register', 'POST', {
            'email': email,
            'password': password,
            'name': name
        })
    
    def login(self, email: str, password: str) -> Dict[str, Any]:
        """Login with email and password."""
        return self._make_request('/login', 'POST', {
            'email': email,
            'password': password
        })
    
    def verify(self, token: str) -> Dict[str, Any]:
        """Verify JWT token."""
        return self._make_request('/verify', 'POST', {
            'token': token
        })
    
    def get_documentation(self) -> Dict[str, Any]:
        """Get API documentation."""
        return self._make_request('/')
    
    def health_check(self) -> Dict[str, Any]:
        """Check service health."""
        return self._make_request('/health')


class OpenJWTAuth:
    """Authentication helper class."""
    
    def __init__(self, api_url: str = API_BASE_URL):
        self.client = OpenJWTClient(api_url)
        self.token: Optional[str] = None
        self.user_data: Optional[Dict] = None
    
    def register(self, email: str, password: str, name: str) -> Dict[str, Any]:
        """Register and automatically set token."""
        result = self.client.register(email, password, name)
        if result['success'] and 'token' in result['data']:
            self.token = result['data']['token']
            self.user_data = result['data']['user']
        return result
    
    def login(self, email: str, password: str) -> Dict[str, Any]:
        """Login and automatically set token."""
        result = self.client.login(email, password)
        if result['success'] and 'token' in result['data']:
            self.token = result['data']['token']
            self.user_data = result['data']['user']
        return result
    
    def verify_current_token(self) -> Dict[str, Any]:
        """Verify the current token."""
        if not self.token:
            return {'success': False, 'message': 'No token available'}
        return self.client.verify(self.token)
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        if not self.token:
            return False
        
        verify_result = self.verify_current_token()
        return verify_result.get('success', False)
    
    def logout(self):
        """Clear authentication data."""
        self.token = None
        self.user_data = None
    
    def get_user_data(self) -> Optional[Dict]:
        """Get current user data."""
        return self.user_data


def run_examples():
    """Run example usage scenarios."""
    client = OpenJWTClient()
    
    print("🚀 OpenJWT Python Client Examples\n")
    
    # Health check
    print("1. Health Check:")
    health = client.health_check()
    print(json.dumps(health, indent=2))
    print()
    
    # Register a user
    print("2. Register User:")
    register_result = client.register(
        'demo@example.com',
        'demo123',
        'Demo User'
    )
    print(json.dumps(register_result, indent=2))
    print()
    
    if register_result['success']:
        token = register_result['data']['token']
        
        # Verify the token
        print("3. Verify Token:")
        verify_result = client.verify(token)
        print(json.dumps(verify_result, indent=2))
        print()
        
        # Login with the same user
        print("4. Login User:")
        login_result = client.login('demo@example.com', 'demo123')
        print(json.dumps(login_result, indent=2))
        print()
    
    # Get API documentation
    print("5. API Documentation:")
    docs = client.get_documentation()
    if docs['success']:
        print(f"Service: {docs['data']['service']}")
        print(f"Available endpoints: {list(docs['data']['endpoints'].keys())}")
    print()


def demonstrate_auth_helper():
    """Demonstrate the authentication helper class."""
    print("🔐 Authentication Helper Example\n")
    
    auth = OpenJWTAuth()
    
    # Register
    print("Registering user...")
    result = auth.register('helper@example.com', 'helper123', 'Helper User')
    print(f"Registration successful: {result['success']}")
    
    if result['success']:
        print(f"User authenticated: {auth.is_authenticated()}")
        print(f"User data: {auth.get_user_data()}")
        
        # Logout and check authentication
        auth.logout()
        print(f"After logout - User authenticated: {auth.is_authenticated()}")


def generate_django_example():
    """Generate Django integration example."""
    return '''
# Django Integration Example for OpenJWT

# settings.py
OPENJWT_API_URL = 'https://your-openjwt-service.herokuapp.com'

# utils/auth.py
import requests
from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.models import User

class OpenJWTAuthBackend:
    def authenticate(self, request, email=None, password=None):
        try:
            response = requests.post(f"{settings.OPENJWT_API_URL}/login", 
                                   json={'email': email, 'password': password})
            
            if response.ok:
                data = response.json()
                if data['success']:
                    # Create or get Django user
                    user, created = User.objects.get_or_create(
                        username=email,
                        defaults={
                            'email': email,
                            'first_name': data['user']['name'].split(' ')[0],
                            'last_name': ' '.join(data['user']['name'].split(' ')[1:]),
                        }
                    )
                    
                    # Store JWT token in session
                    request.session['jwt_token'] = data['token']
                    return user
        except requests.RequestException:
            pass
        
        return None
    
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

# views.py
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages

def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        user = authenticate(request, email=email, password=password)
        if user:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid credentials')
    
    return render(request, 'login.html')

def verify_jwt_token(request):
    """Middleware to verify JWT token on each request."""
    token = request.session.get('jwt_token')
    if token:
        try:
            response = requests.post(f"{settings.OPENJWT_API_URL}/verify",
                                   json={'token': token})
            if not response.ok:
                # Token invalid, logout user
                request.session.flush()
                return redirect('login')
        except requests.RequestException:
            pass
'''


if __name__ == '__main__':
    # Run basic examples
    run_examples()
    
    # Demonstrate auth helper
    demonstrate_auth_helper()
    
    # Print Django example
    print("\n📄 Django Integration Example:")
    print(generate_django_example())
    
    print("\n✨ More examples available in the documentation!")
