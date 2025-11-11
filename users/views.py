import json
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password, check_password
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import parse_json_body

User = get_user_model()


@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(View):
    """Register a new user"""
    def post(self, request):
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'customer')
        
        if not username or not email or not password:
            return JsonResponse({
                'status': 'error',
                'message': 'Username, email, and password are required'
            }, status=400)
        
        if role not in ['manager', 'customer']:
            return JsonResponse({
                'status': 'error',
                'message': 'Role must be either "manager" or "customer"'
            }, status=400)
        
        if User.objects.filter(username=username).exists():
            return JsonResponse({
                'status': 'error',
                'message': 'Username already exists'
            }, status=400)
        
        if User.objects.filter(email=email).exists():
            return JsonResponse({
                'status': 'error',
                'message': 'Email already exists'
            }, status=400)
        
        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                role=role
            )
            refresh = RefreshToken.for_user(user)
            return JsonResponse({
                'status': 'success',
                'message': 'User registered successfully',
                'data': {
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'role': user.role
                    },
                    'tokens': {
                        'access': str(refresh.access_token),
                        'refresh': str(refresh)
                    }
                }
            }, status=201)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f'Registration failed: {str(e)}'
            }, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class LoginView(View):
    """Login and get JWT tokens"""
    def post(self, request):
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return JsonResponse({
                'status': 'error',
                'message': 'Username and password are required'
            }, status=400)
        
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid credentials'
            }, status=401)
        
        if not user.check_password(password):
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid credentials'
            }, status=401)
        
        refresh = RefreshToken.for_user(user)
        return JsonResponse({
            'status': 'success',
            'message': 'Login successful',
            'data': {
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role
                },
                'tokens': {
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)
                }
            }
        })


@method_decorator(csrf_exempt, name='dispatch')
class ResetPasswordView(View):
    """Reset password via email/username"""
    def post(self, request):
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        
        username_or_email = data.get('username') or data.get('email')
        new_password = data.get('new_password')
        
        if not username_or_email or not new_password:
            return JsonResponse({
                'status': 'error',
                'message': 'Username/email and new password are required'
            }, status=400)
        
        try:
            if '@' in username_or_email:
                user = User.objects.get(email=username_or_email)
            else:
                user = User.objects.get(username=username_or_email)
        except User.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'User not found'
            }, status=404)
        
        user.set_password(new_password)
        user.save()
        
        return JsonResponse({
            'status': 'success',
            'message': 'Password reset successfully'
        })
