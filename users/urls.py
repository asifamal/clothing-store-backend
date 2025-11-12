from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    RegisterView,
    LoginView,
    ResetPasswordView,
    RequestOTPView,
    VerifyOTPView,
    ResetPasswordWithOTPView,
    CheckUsernameView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset_password'),
    path('request-otp/', RequestOTPView.as_view(), name='request_otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('reset-password-otp/', ResetPasswordWithOTPView.as_view(), name='reset_password_otp'),
    path('check-username/', CheckUsernameView.as_view(), name='check_username'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]


