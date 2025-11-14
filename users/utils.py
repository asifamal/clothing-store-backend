"""
JWT Authentication utilities for manual JSON handling
"""
import json
from functools import wraps
from django.http import JsonResponse
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.contrib.auth import get_user_model

User = get_user_model()


def get_user_from_token(request):
    """
    Extract user from JWT token in Authorization header
    Returns (user, error_response) tuple
    """
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    
    if not auth_header.startswith('Bearer '):
        return None, JsonResponse({
            'status': 'error',
            'message': 'Authorization header missing or invalid'
        }, status=401)
    
    try:
        token = auth_header.split(' ')[1]
        validated_token = UntypedToken(token)
        user_id = validated_token['user_id']
        user = User.objects.get(id=user_id)
        return user, None
    except (TokenError, InvalidToken, User.DoesNotExist, IndexError) as e:
        return None, JsonResponse({
            'status': 'error',
            'message': 'Invalid or expired token'
        }, status=401)


def authenticate_request(request):
    """
    Extract and return user from JWT token in Authorization header
    Returns user object or None if authentication fails
    Compatible with REST framework style
    """
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    
    if not auth_header.startswith('Bearer '):
        return None
    
    try:
        token = auth_header.split(' ')[1]
        validated_token = UntypedToken(token)
        user_id = validated_token['user_id']
        user = User.objects.get(id=user_id)
        return user
    except (TokenError, InvalidToken, User.DoesNotExist, IndexError):
        return None


def jwt_required(view_func):
    """
    Decorator to require JWT authentication
    Adds 'user' to request object
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user, error_response = get_user_from_token(request)
        if error_response:
            return error_response
        request.user = user
        return view_func(request, *args, **kwargs)
    return wrapper


def manager_required(view_func):
    """
    Decorator to require manager role
    Must be used after @jwt_required
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not hasattr(request, 'user') or not request.user.is_manager:
            return JsonResponse({
                'status': 'error',
                'message': 'Manager access required'
            }, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


def parse_json_body(request):
    """
    Parse JSON from request body
    Returns (data, error_response) tuple
    """
    try:
        body = request.body.decode('utf-8')
        if not body:
            return {}, None
        data = json.loads(body)
        return data, None
    except json.JSONDecodeError:
        return None, JsonResponse({
            'status': 'error',
            'message': 'Invalid JSON format'
        }, status=400)

