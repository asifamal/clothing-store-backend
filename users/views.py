import json
import random
import string
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import send_mail
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import parse_json_body
from .models import PasswordResetOTP

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
            # Allow login using either username or email. The frontend sends the
            # value in the `username` field but the input accepts an email as
            # well. If the value contains an '@' character, attempt to find the
            # user by email first.
            if '@' in username:
                user = User.objects.get(email=username)
            else:
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
class CheckUsernameView(View):
    """Check whether a username is already taken
    GET param: ?username=<username>
    Returns: { available: true|false }
    """
    def get(self, request):
        username = request.GET.get('username')
        if not username:
            return JsonResponse({
                'status': 'error',
                'message': 'username query parameter is required'
            }, status=400)

        exists = User.objects.filter(username=username).exists()
        return JsonResponse({'available': not exists})


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


def generate_otp():
    """Generate a random 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))


def send_otp_email(user_email, otp_code):
    """Send OTP to user's email"""
    try:
        print(otp_code)
        subject = "Your Password Reset OTP - NOTED STORE"
        message = f"""
Hello,

You requested to reset your password on NOTED STORE.

Your One-Time Password (OTP) is: {otp_code}

This OTP is valid for 10 minutes. Do not share this code with anyone.

If you didn't request this, please ignore this email.

Best regards,
NOTED STORE Team
        """
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user_email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending OTP email: {str(e)}")
        return False


@method_decorator(csrf_exempt, name='dispatch')
class RequestOTPView(View):
    """Request an OTP for password reset"""
    def post(self, request):
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        
        username_or_email = data.get('username') or data.get('email')
        
        if not username_or_email:
            return JsonResponse({
                'status': 'error',
                'message': 'Username or email is required'
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
        
        # Clear expired OTPs (older than 10 minutes)
        ten_minutes_ago = timezone.now() - timedelta(minutes=10)
        PasswordResetOTP.objects.filter(user=user, created_at__lt=ten_minutes_ago).delete()
        
        # Check if user has an active OTP
        active_otp = PasswordResetOTP.objects.filter(user=user, is_used=False).first()
        if active_otp:
            otp_code = active_otp.code
        else:
            # Generate new OTP
            otp_code = generate_otp()
            PasswordResetOTP.objects.create(user=user, code=otp_code)
        
        # Send OTP to email
        if send_otp_email(user.email, otp_code):
            return JsonResponse({
                'status': 'success',
                'message': f'OTP sent to {user.email}',
                'data': {
                    'email_masked': user.email[:2] + '*' * (len(user.email) - 4) + user.email[-2:]
                }
            })
        else:
            return JsonResponse({
                'status': 'error',
                'message': 'Failed to send OTP email'
            }, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class VerifyOTPView(View):
    """Verify OTP code"""
    def post(self, request):
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        
        username_or_email = data.get('username') or data.get('email')
        otp_code = data.get('otp')
        
        if not username_or_email or not otp_code:
            return JsonResponse({
                'status': 'error',
                'message': 'Username/email and OTP are required'
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
        
        # Find the OTP
        try:
            otp_record = PasswordResetOTP.objects.get(
                user=user,
                code=otp_code,
                is_used=False
            )
        except PasswordResetOTP.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid or expired OTP'
            }, status=400)
        
        # Check if OTP is expired (10 minutes)
        if timezone.now() - otp_record.created_at > timedelta(minutes=10):
            return JsonResponse({
                'status': 'error',
                'message': 'OTP has expired'
            }, status=400)
        
        return JsonResponse({
            'status': 'success',
            'message': 'OTP verified successfully'
        })


@method_decorator(csrf_exempt, name='dispatch')
class ResetPasswordWithOTPView(View):
    """Reset password using OTP"""
    def post(self, request):
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        
        username_or_email = data.get('username') or data.get('email')
        otp_code = data.get('otp')
        new_password = data.get('new_password')
        
        if not username_or_email or not otp_code or not new_password:
            return JsonResponse({
                'status': 'error',
                'message': 'Username/email, OTP, and new password are required'
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
        
        # Find and verify the OTP
        try:
            otp_record = PasswordResetOTP.objects.get(
                user=user,
                code=otp_code,
                is_used=False
            )
        except PasswordResetOTP.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid or expired OTP'
            }, status=400)
        
        # Check if OTP is expired
        if timezone.now() - otp_record.created_at > timedelta(minutes=10):
            return JsonResponse({
                'status': 'error',
                'message': 'OTP has expired'
            }, status=400)
        
        # Reset password
        user.set_password(new_password)
        user.save()
        
        # Mark OTP as used
        otp_record.is_used = True
        otp_record.save()
        
        return JsonResponse({
            'status': 'success',
            'message': 'Password reset successfully'
        })
