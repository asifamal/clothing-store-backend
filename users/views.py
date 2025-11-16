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
from .models import PasswordResetOTP, UserProfile

from rest_framework_simplejwt.authentication import JWTAuthentication
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt


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
                        'role': user.role,
                        'phone_number': ''
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
        
        # Get user's profile phone number if it exists
        phone_number = ''
        try:
            profile = user.profile
            phone_number = profile.phone_number or ''
        except UserProfile.DoesNotExist:
            pass
        
        refresh = RefreshToken.for_user(user)
        return JsonResponse({
            'status': 'success',
            'message': 'Login successful',
            'data': {
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'phone_number': phone_number
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


def authenticate_request(request):
    """Authenticate request using JWT from Authorization header.
    Returns user or None.
    """
    auth = JWTAuthentication()
    try:
        user_auth_tuple = auth.authenticate(request)
        if user_auth_tuple is None:
            return None
        user, token = user_auth_tuple
        return user
    except Exception:
        return None


@method_decorator(csrf_exempt, name='dispatch')
class AdminUsersView(View):
    """List all users (GET) - manager only"""
    def get(self, request):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        users = User.objects.all().values('id', 'username', 'email', 'role', 'is_staff', 'is_superuser')
        return JsonResponse({'status': 'success', 'data': list(users)})


@method_decorator(csrf_exempt, name='dispatch')
class AdminUserDetailView(View):
    """Retrieve, update or delete a user by id (manager only)"""
    def get(self, request, pk):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        try:
            u = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User not found'}, status=404)

        return JsonResponse({'status': 'success', 'data': {'id': u.id, 'username': u.username, 'email': u.email, 'role': u.role}})

    def put(self, request, pk):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        data, error_response = parse_json_body(request)
        if error_response:
            return error_response

        try:
            u = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User not found'}, status=404)

        username = data.get('username')
        email = data.get('email')
        role = data.get('role')
        password = data.get('password')

        if username:
            u.username = username
        if email:
            u.email = email
        if role in ['manager', 'customer']:
            u.role = role
        if password:
            u.set_password(password)

        u.save()
        return JsonResponse({'status': 'success', 'message': 'User updated'})

    def delete(self, request, pk):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        try:
            u = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User not found'}, status=404)

        u.delete()
        return JsonResponse({'status': 'success', 'message': 'User deleted'})


@method_decorator(csrf_exempt, name='dispatch')
class AdminDashboardStatsView(View):
    """Admin dashboard statistics - manager only"""
    def get(self, request):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import Product
        from orders.models import Order, OrderItem

        # Current period stats
        current_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        previous_start = (current_start - timedelta(days=1)).replace(day=1)
        previous_end = current_start - timedelta(seconds=1)

        # Total revenue (current month)
        orders_current = Order.objects.filter(
            status__in=['delivered', 'dispatched', 'confirmed'],
            created_at__gte=current_start
        )
        total_revenue = sum(float(o.total_amount) for o in orders_current)

        # Previous month revenue
        orders_previous = Order.objects.filter(
            status__in=['delivered', 'dispatched', 'confirmed'],
            created_at__gte=previous_start,
            created_at__lte=previous_end
        )
        previous_revenue = sum(float(o.total_amount) for o in orders_previous)
        revenue_change = ((total_revenue - previous_revenue) / previous_revenue * 100) if previous_revenue > 0 else 0

        # New users (last 30 days vs previous 30 days)
        thirty_days_ago = timezone.now() - timedelta(days=30)
        sixty_days_ago = timezone.now() - timedelta(days=60)
        new_users_current = User.objects.filter(created_at__gte=thirty_days_ago).count()
        new_users_previous = User.objects.filter(
            created_at__gte=sixty_days_ago,
            created_at__lt=thirty_days_ago
        ).count()
        users_change = ((new_users_current - new_users_previous) / max(new_users_previous, 1) * 100)

        # Total customers
        total_customers = User.objects.filter(role='customer').count()

        # Total products
        total_products = Product.objects.count()

        # Total orders (current month vs previous month)
        total_orders_current = Order.objects.filter(created_at__gte=current_start).count()
        total_orders_previous = Order.objects.filter(
            created_at__gte=previous_start,
            created_at__lte=previous_end
        ).count()
        orders_change = ((total_orders_current - total_orders_previous) / max(total_orders_previous, 1) * 100)

        # Page views (derived from order count)
        page_views = Order.objects.count() * 12  # Approximate page views

        return JsonResponse({
            'status': 'success',
            'data': {
                'total_revenue': round(total_revenue, 2),
                'revenue_change': round(revenue_change, 1),
                'new_users': new_users_current,
                'users_change': round(users_change, 1),
                'total_customers': total_customers,
                'total_products': total_products,
                'total_orders': total_orders_current,
                'orders_change': round(orders_change, 1),
                'page_views': page_views,
            }
        })


@method_decorator(csrf_exempt, name='dispatch')
class AdminOrdersView(View):
    """List orders with filters - manager only"""
    def get(self, request):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from orders.models import Order

        status_filter = request.GET.get('status')
        limit = int(request.GET.get('limit', 10))
        offset = int(request.GET.get('offset', 0))

        orders = Order.objects.all()
        if status_filter and status_filter != 'all':
            orders = orders.filter(status=status_filter)

        total_count = orders.count()
        orders = orders.order_by('-created_at')[offset:offset+limit]

        data = []
        for o in orders:
            data.append({
                'id': o.id,
                'customer': o.user.username,
                'total_amount': float(o.total_amount),
                'status': o.status,
                'created_at': o.created_at.isoformat(),
                'items_count': o.items.count(),
            })

        return JsonResponse({
            'status': 'success',
            'data': data,
            'total': total_count,
        })


@method_decorator(csrf_exempt, name='dispatch')
class AdminProductsView(View):
    """List products with filters - manager only"""
    def get(self, request):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import Product

        category_filter = request.GET.get('category')
        search = request.GET.get('search', '')
        limit = int(request.GET.get('limit', 10))
        offset = int(request.GET.get('offset', 0))

        products = Product.objects.all()
        if category_filter and category_filter != 'all':
            products = products.filter(category__name=category_filter)

        if search:
            products = products.filter(name__icontains=search)

        total_count = products.count()
        products = products.order_by('-created_at')[offset:offset+limit]

        data = []
        for p in products:
            data.append({
                'id': p.id,
                'name': p.name,
                'price': float(p.price),
                'stock': p.stock,
                'category': p.category.name if p.category else 'Uncategorized',
                'created_at': p.created_at.isoformat(),
            })

        return JsonResponse({
            'status': 'success',
            'data': data,
            'total': total_count,
        })


@method_decorator(csrf_exempt, name='dispatch')
class AdminSalesChartView(View):
    """Sales over time chart data - manager only"""
    def get(self, request):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from orders.models import Order

        # Last 7 days sales data
        days_data = []
        for i in range(6, -1, -1):
            date = timezone.now() - timedelta(days=i)
            day_orders = Order.objects.filter(created_at__date=date.date(), status__in=['delivered', 'dispatched', 'confirmed'])
            daily_total = sum(float(o.total_amount) for o in day_orders)
            days_data.append({
                'day': date.strftime('%a'),
                'sales': round(daily_total, 2)
            })

        return JsonResponse({
            'status': 'success',
            'data': days_data
        })


@method_decorator(csrf_exempt, name='dispatch')
class AdminAllCategoriesView(View):
    """Get all categories for dropdown - manager only"""
    def get(self, request):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import Category

        categories = Category.objects.all().values('id', 'name')
        data = [{'id': c['id'], 'name': c['name']} for c in categories]

        return JsonResponse({
            'status': 'success',
            'data': data,
        })


@method_decorator(csrf_exempt, name='dispatch')
class AdminCategoriesView(View):
    """List, create, update, delete categories - manager only"""
    def get(self, request):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import Category

        categories = Category.objects.all().values('id', 'name', 'description', 'created_at')
        return JsonResponse({'status': 'success', 'data': list(categories)})

    def post(self, request):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import Category

        data, error_response = parse_json_body(request)
        if error_response:
            return error_response

        name = data.get('name', '').strip()
        description = data.get('description', '').strip()

        if not name:
            return JsonResponse({'status': 'error', 'message': 'Category name is required'}, status=400)

        if Category.objects.filter(name=name).exists():
            return JsonResponse({'status': 'error', 'message': 'Category already exists'}, status=400)

        category = Category.objects.create(name=name, description=description)
        return JsonResponse({
            'status': 'success',
            'message': 'Category created',
            'data': {
                'id': category.id,
                'name': category.name,
                'description': category.description,
                'created_at': category.created_at.isoformat(),
            }
        })


@method_decorator(csrf_exempt, name='dispatch')
class AdminCategoryDetailView(View):
    """Get, update, delete category by id - manager only"""
    def get(self, request, pk):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import Category

        try:
            category = Category.objects.get(pk=pk)
        except Category.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Category not found'}, status=404)

        return JsonResponse({
            'status': 'success',
            'data': {
                'id': category.id,
                'name': category.name,
                'description': category.description,
                'created_at': category.created_at.isoformat(),
            }
        })

    def put(self, request, pk):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import Category

        data, error_response = parse_json_body(request)
        if error_response:
            return error_response

        try:
            category = Category.objects.get(pk=pk)
        except Category.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Category not found'}, status=404)

        name = data.get('name', '').strip()
        description = data.get('description', '').strip()

        if name and name != category.name:
            if Category.objects.filter(name=name).exists():
                return JsonResponse({'status': 'error', 'message': 'Category name already exists'}, status=400)
            category.name = name

        if description:
            category.description = description

        category.save()
        return JsonResponse({
            'status': 'success',
            'message': 'Category updated',
            'data': {
                'id': category.id,
                'name': category.name,
                'description': category.description,
                'updated_at': category.updated_at.isoformat(),
            }
        })

    def delete(self, request, pk):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import Category

        try:
            category = Category.objects.get(pk=pk)
        except Category.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Category not found'}, status=404)

        category.delete()
        return JsonResponse({'status': 'success', 'message': 'Category deleted'})


@method_decorator(csrf_exempt, name='dispatch')
class AdminProductsDetailView(View):
    """Get, update, delete product by id - manager only"""
    def get(self, request, pk):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import Product

        try:
            product = Product.objects.prefetch_related('variants').get(pk=pk)
        except Product.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Product not found'}, status=404)

        # Get variants data
        variants_data = []
        for variant in product.variants.all():
            variants_data.append({
                'id': variant.id,
                'size': variant.size,
                'stock': variant.stock,
            })

        # Get attributes data
        attributes_data = []
        for attr in product.attributes.all():
            attributes_data.append({
                'id': attr.category_attribute.id,
                'name': attr.category_attribute.name,
                'value': attr.value,
            })

        return JsonResponse({
            'status': 'success',
            'data': {
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': float(product.price),
                'stock': product.stock,
                'category_id': product.category.id if product.category else None,
                'category_name': product.category.name if product.category else None,
                'image': product.image.url if product.image else None,
                'variants': variants_data,
                'attributes': attributes_data,
                'created_at': product.created_at.isoformat(),
            }
        })

    def put(self, request, pk):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import Product, Category

        try:
            product = Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Product not found'}, status=404)

        # Handle both JSON and multipart form data
        if request.content_type and 'application/json' in request.content_type:
            data, error_response = parse_json_body(request)
            if error_response:
                return error_response
        else:
            # Multipart form data (from FormData)
            data = request.POST.dict()

        if 'name' in data and data['name']:
            product.name = data['name'].strip()
        if 'description' in data:
            product.description = data['description'].strip()
        if 'price' in data and data['price']:
            try:
                product.price = float(data['price'])
            except (ValueError, TypeError):
                return JsonResponse({'status': 'error', 'message': 'Invalid price'}, status=400)
        if 'stock' in data and data['stock']:
            try:
                product.stock = int(data['stock'])
            except (ValueError, TypeError):
                return JsonResponse({'status': 'error', 'message': 'Invalid stock'}, status=400)
        if 'category_id' in data and data['category_id']:
            try:
                product.category = Category.objects.get(id=data['category_id'])
            except Category.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Category not found'}, status=404)

        # Handle image upload
        if 'image' in request.FILES:
            product.image = request.FILES['image']

        product.save()

        # Handle attributes update
        from products.models import ProductAttribute, CategoryAttribute
        if request.content_type and 'multipart/form-data' in request.content_type:
            # Update attributes from form data
            for key, value in request.POST.items():
                if key.startswith('attr_') and value.strip():
                    attr_id = key.replace('attr_', '')
                    try:
                        category_attribute = CategoryAttribute.objects.get(id=attr_id, category=product.category)
                        ProductAttribute.objects.update_or_create(
                            product=product,
                            category_attribute=category_attribute,
                            defaults={'value': value.strip()}
                        )
                    except CategoryAttribute.DoesNotExist:
                        pass

        return JsonResponse({
            'status': 'success',
            'message': 'Product updated',
            'data': {
                'id': product.id,
                'name': product.name,
                'price': float(product.price),
                'stock': product.stock,
            }
        })

    def delete(self, request, pk):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import Product

        try:
            product = Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Product not found'}, status=404)

        product.delete()
        return JsonResponse({'status': 'success', 'message': 'Product deleted'})


@method_decorator(csrf_exempt, name='dispatch')
class AdminCreateProductView(View):
    """Create product - manager only"""
    def post(self, request):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import Product, Category

        # Handle multipart form data (when image is uploaded)
        name = request.POST.get('name', '').strip()
        description = request.POST.get('description', '').strip()
        price = request.POST.get('price')
        stock = request.POST.get('stock', 0)
        category_id = request.POST.get('category_id')
        image = request.FILES.get('image') if 'image' in request.FILES else None

        if not name:
            return JsonResponse({'status': 'error', 'message': 'Product name is required'}, status=400)
        if not price:
            return JsonResponse({'status': 'error', 'message': 'Price is required'}, status=400)

        try:
            price = float(price)
            stock = int(stock)
        except (ValueError, TypeError):
            return JsonResponse({'status': 'error', 'message': 'Invalid price or stock'}, status=400)

        try:
            category = Category.objects.get(id=category_id) if category_id else None
        except Category.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Category not found'}, status=404)

        product = Product.objects.create(
            name=name,
            description=description,
            price=price,
            stock=stock,
            category=category,
            image=image,
        )

        # Handle attributes if provided
        from products.models import ProductAttribute, CategoryAttribute
        
        print(f"DEBUG: ===== Processing attributes for product '{name}' =====")
        print(f"DEBUG: Category: {category} (id: {category.id})")
        print(f"DEBUG: All POST data keys: {list(request.POST.keys())}")
        print(f"DEBUG: POST data dict: {dict(request.POST)}")
        
        # Check if any attr_ keys exist
        attr_keys = [key for key in request.POST.keys() if key.startswith('attr_')]
        print(f"DEBUG: Found {len(attr_keys)} attribute keys: {attr_keys}")
        
        if not attr_keys:
            print("DEBUG: No attribute keys found in POST data")
        
        for key, value in request.POST.items():
            print(f"DEBUG: Processing POST item: {key} = '{value}'")
            if key.startswith('attr_') and value.strip():
                attr_id = key.replace('attr_', '')
                print(f"DEBUG: Processing attribute - key: '{key}', value: '{value}', attr_id: '{attr_id}'")
                try:
                    attr_id_int = int(attr_id)
                    print(f"DEBUG: Looking for CategoryAttribute with id={attr_id_int} and category={category.id}")
                    
                    # Check if the category attribute exists
                    category_attribute = CategoryAttribute.objects.get(id=attr_id_int, category=category)
                    print(f"DEBUG: Found CategoryAttribute: {category_attribute.name} (type: {category_attribute.attribute_type})")
                    
                    # Create the product attribute
                    product_attr = ProductAttribute.objects.create(
                        product=product,
                        category_attribute=category_attribute,
                        value=value.strip()
                    )
                    print(f"DEBUG: ✓ Successfully saved ProductAttribute: {product_attr}")
                    
                except ValueError as e:
                    print(f"DEBUG: ✗ Invalid attr_id '{attr_id}': {e}")
                except CategoryAttribute.DoesNotExist:
                    print(f"DEBUG: ✗ CategoryAttribute with id {attr_id_int} not found for category {category} (id: {category.id})")
                    # Let's see what attributes ARE available for this category
                    available_attrs = CategoryAttribute.objects.filter(category=category)
                    print(f"DEBUG: Available CategoryAttributes for category {category}: {[(a.id, a.name) for a in available_attrs]}")
                except Exception as e:
                    print(f"DEBUG: ✗ Unexpected error processing attribute {key}: {e}")
            elif key.startswith('attr_'):
                print(f"DEBUG: Skipping empty/whitespace attribute: {key} = '{value}'")
        
        print("DEBUG: ===== Finished processing attributes =====")
        
        # Final check - let's see what attributes were actually saved
        saved_attrs = ProductAttribute.objects.filter(product=product)
        print(f"DEBUG: Final check - {saved_attrs.count()} attributes saved for product {product.id}")
        for attr in saved_attrs:
            print(f"DEBUG: Saved: {attr.category_attribute.name} = {attr.value}")

        return JsonResponse({
            'status': 'success',
            'message': 'Product created',
            'data': {
                'id': product.id,
                'name': product.name,
                'price': float(product.price),
                'stock': product.stock,
            }
        })


@method_decorator(csrf_exempt, name='dispatch')
class AdminOrderDetailView(View):
    """Get, update order by id - manager only"""
    def get(self, request, pk):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from orders.models import Order

        try:
            order = Order.objects.get(pk=pk)
        except Order.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Order not found'}, status=404)

        items = []
        for item in order.items.all():
            items.append({
                'id': item.id,
                'product_name': item.product.name,
                'quantity': item.quantity,
                'price': float(item.price),
                'total': float(item.total_price),
            })

        return JsonResponse({
            'status': 'success',
            'data': {
                'id': order.id,
                'customer': order.user.username,
                'email': order.user.email,
                'contact_phone': order.contact_phone or '',
                'total_amount': float(order.total_amount),
                'status': order.status,
                'awb_number': order.awb_number or '',
                'courier_partner': order.courier_partner or '',
                'created_at': order.created_at.isoformat(),
                'updated_at': order.updated_at.isoformat(),
                'items': items,
                'address': {
                    'street': order.address.street_address if order.address else '',
                    'city': order.address.city if order.address else '',
                    'state': order.address.state if order.address else '',
                    'zip': order.address.zip_code if order.address else '',
                } if order.address else None,
            }
        })

    def put(self, request, pk):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from orders.models import Order

        try:
            order = Order.objects.get(pk=pk)
        except Order.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Order not found'}, status=404)

        data, error_response = parse_json_body(request)
        if error_response:
            return error_response

        if 'status' in data:
            valid_statuses = ['pending', 'confirmed', 'dispatched', 'delivered', 'cancelled']
            if data['status'] not in valid_statuses:
                return JsonResponse({'status': 'error', 'message': f'Invalid status. Must be one of: {valid_statuses}'})
            
            # Check if trying to change a cancelled order
            if order.status == 'cancelled':
                return JsonResponse({
                    'status': 'error',
                    'message': 'Cannot change status of a cancelled order'
                })
            
            # Prevent cancelling orders that are dispatched or delivered
            if data['status'] == 'cancelled' and order.status in ['dispatched', 'delivered']:
                return JsonResponse({
                    'status': 'error',
                    'message': f'Cannot cancel an order that has been {order.status}. Please contact the customer to arrange a return.'
                })
            
            # If changing to dispatched, require AWB and courier partner
            if data['status'] == 'dispatched':
                awb_number = data.get('awb_number', '').strip()
                courier_partner = data.get('courier_partner', '').strip()
                
                if not awb_number or not courier_partner:
                    return JsonResponse({
                        'status': 'error',
                        'message': 'AWB number and courier partner are required for dispatch'
                    })
                
                order.awb_number = awb_number
                order.courier_partner = courier_partner
            
            # Try to save, catch ValidationError from signal
            try:
                order.status = data['status']
                order.save()
            except Exception as e:
                from django.core.exceptions import ValidationError
                if isinstance(e, ValidationError):
                    error_message = e.messages[0] if hasattr(e, 'messages') and e.messages else str(e)
                    return JsonResponse({
                        'status': 'error',
                        'message': error_message
                    })
                # Re-raise other exceptions
                raise

        return JsonResponse({
            'status': 'success',
            'message': 'Order updated',
            'data': {
                'id': order.id,
                'status': order.status,
                'updated_at': order.updated_at.isoformat(),
            }
        })


@method_decorator(csrf_exempt, name='dispatch')
class AdminCategoryAttributesView(View):
    """Get category attributes - manager only"""
    def get(self, request, category_id):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import CategoryAttribute, CategoryAttributeOption

        try:
            attributes = CategoryAttribute.objects.filter(category_id=category_id).prefetch_related('options')
            attributes_data = []
            for attr in attributes:
                attr_data = {
                    'id': attr.id,
                    'name': attr.name,
                    'field_type': attr.attribute_type,  # Map to frontend field name
                    'is_required': attr.is_required,
                    'options': [{'id': opt.id, 'value': opt.value} for opt in attr.options.all()]
                }
                attributes_data.append(attr_data)

            return JsonResponse({
                'status': 'success',
                'data': {
                    'attributes': attributes_data
                }
            })
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

    def post(self, request, category_id):
        """Create new category attribute"""
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import Category, CategoryAttribute, CategoryAttributeOption

        try:
            data, error = parse_json_body(request)
            if error:
                return error
            
            # Validate category exists
            if not Category.objects.filter(id=category_id).exists():
                return JsonResponse({'status': 'error', 'message': 'Category not found'}, status=404)

            # Create attribute
            attribute = CategoryAttribute.objects.create(
                category_id=category_id,
                name=data['name'],
                attribute_type=data['field_type'],  # Map from frontend field name
                is_required=data.get('is_required', False)
            )

            # Create options if select type
            if data['field_type'] == 'select' and 'options' in data:
                for option_value in data['options']:
                    if option_value.strip():
                        CategoryAttributeOption.objects.create(
                            attribute=attribute,
                            value=option_value.strip()
                        )

            return JsonResponse({
                'status': 'success',
                'data': {'id': attribute.id, 'message': 'Attribute created successfully'}
            })
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class AdminDeleteCategoryAttributeView(View):
    """Delete category attribute - manager only"""
    def delete(self, request, category_id, attribute_id):
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import CategoryAttribute

        try:
            attribute = CategoryAttribute.objects.get(id=attribute_id, category_id=category_id)
            attribute.delete()

            return JsonResponse({
                'status': 'success',
                'data': {'message': 'Attribute deleted successfully'}
            })
        except CategoryAttribute.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Attribute not found'}, status=404)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class AdminProductVariantsView(View):
    """Manage product variants (sizes and stock) - manager only"""
    def get(self, request, product_id):
        """Get all variants for a product"""
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import Product, ProductVariant

        try:
            product = Product.objects.get(pk=product_id)
        except Product.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Product not found'}, status=404)

        variants = ProductVariant.objects.filter(product=product)
        variants_data = []
        for variant in variants:
            variants_data.append({
                'id': variant.id,
                'size': variant.size,
                'stock': variant.stock,
            })

        return JsonResponse({
            'status': 'success',
            'data': {'variants': variants_data}
        })

    def post(self, request, product_id):
        """Create or update variants for a product"""
        user = authenticate_request(request)
        if not user or getattr(user, 'role', None) != 'manager':
            return JsonResponse({'status': 'error', 'message': 'Forbidden'}, status=403)

        from products.models import Product, ProductVariant

        try:
            product = Product.objects.get(pk=product_id)
        except Product.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Product not found'}, status=404)

        data, error_response = parse_json_body(request)
        if error_response:
            return error_response

        # Expecting array of variants: [{"size": "M", "stock": 10}, ...]
        variants = data.get('variants', [])
        
        if not isinstance(variants, list):
            return JsonResponse({'status': 'error', 'message': 'Variants must be an array'}, status=400)

        created_variants = []
        for variant_data in variants:
            size = variant_data.get('size')
            stock = variant_data.get('stock', 0)

            if not size:
                continue

            # Create or update variant
            variant, created = ProductVariant.objects.update_or_create(
                product=product,
                size=size,
                defaults={'stock': stock}
            )
            created_variants.append({
                'id': variant.id,
                'size': variant.size,
                'stock': variant.stock,
            })

        # Update total product stock
        total_stock = sum(v.stock for v in ProductVariant.objects.filter(product=product))
        product.stock = total_stock
        product.save()

        return JsonResponse({
            'status': 'success',
            'message': 'Variants updated',
            'data': {'variants': created_variants}
        })


# User Profile Views

@method_decorator(csrf_exempt, name='dispatch')
class UserProfileView(View):
    """Get and update user profile"""
    
    def get(self, request):
        """Get current user profile"""
        user = authenticate_request(request)
        if not user:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        from .models import UserProfile
        
        try:
            profile = UserProfile.objects.get(user=user)
            profile_data = {
                'id': profile.id,
                'first_name': profile.first_name,
                'last_name': profile.last_name,
                'date_of_birth': profile.date_of_birth.isoformat() if profile.date_of_birth else None,
                'phone_number': profile.phone_number,
                'avatar': profile.avatar.url if profile.avatar else None,
                'bio': profile.bio,
                'created_at': profile.created_at.isoformat(),
                'updated_at': profile.updated_at.isoformat(),
            }
        except UserProfile.DoesNotExist:
            # Return empty profile structure if doesn't exist
            profile_data = {
                'id': None,
                'first_name': '',
                'last_name': '',
                'date_of_birth': None,
                'phone_number': '',
                'avatar': None,
                'bio': '',
                'created_at': None,
                'updated_at': None,
            }
        
        return JsonResponse({
            'status': 'success',
            'data': {
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                },
                'profile': profile_data
            }
        })
    
    def post(self, request):
        """Create or update user profile"""
        user = authenticate_request(request)
        if not user:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        from .models import UserProfile
        
        # Handle both JSON and multipart form data
        if request.content_type and 'application/json' in request.content_type:
            data, error_response = parse_json_body(request)
            if error_response:
                return error_response
        else:
            # Multipart form data (when avatar is uploaded)
            data = request.POST.dict()
        
        # Get or create profile
        profile, created = UserProfile.objects.get_or_create(user=user)
        
        # Update profile fields
        if 'first_name' in data:
            profile.first_name = data['first_name'].strip()
        if 'last_name' in data:
            profile.last_name = data['last_name'].strip()
        if 'date_of_birth' in data and data['date_of_birth']:
            from datetime import datetime
            try:
                profile.date_of_birth = datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date()
            except ValueError:
                return JsonResponse({'status': 'error', 'message': 'Invalid date format. Use YYYY-MM-DD'}, status=400)
        if 'phone_number' in data:
            profile.phone_number = data['phone_number'].strip()
        if 'bio' in data:
            profile.bio = data['bio'].strip()
        
        # Handle avatar upload
        if 'avatar' in request.FILES:
            profile.avatar = request.FILES['avatar']
        
        profile.save()
        
        return JsonResponse({
            'status': 'success',
            'message': 'Profile updated successfully',
            'data': {
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'phone_number': profile.phone_number
                },
                'profile': {
                    'id': profile.id,
                    'first_name': profile.first_name,
                    'last_name': profile.last_name,
                    'date_of_birth': profile.date_of_birth.isoformat() if profile.date_of_birth else None,
                    'phone_number': profile.phone_number,
                    'avatar': profile.avatar.url if profile.avatar else None,
                    'bio': profile.bio,
                    'updated_at': profile.updated_at.isoformat(),
                }
            }
        })


@method_decorator(csrf_exempt, name='dispatch')
class UserAddressesView(View):
    """Manage user addresses"""
    
    def get(self, request):
        """Get all user addresses"""
        user = authenticate_request(request)
        if not user:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        from .models import UserAddress
        
        addresses = UserAddress.objects.filter(user=user).order_by('-is_default', '-created_at')
        addresses_data = []
        
        for address in addresses:
            addresses_data.append({
                'id': address.id,
                'address_type': address.address_type,
                'street_address': address.street_address,
                'apartment_number': address.apartment_number,
                'city': address.city,
                'state': address.state,
                'zip_code': address.zip_code,
                'country': address.country,
                'is_default': address.is_default,
                'created_at': address.created_at.isoformat(),
            })
        
        return JsonResponse({
            'status': 'success',
            'data': addresses_data
        })
    
    def post(self, request):
        """Create new address"""
        user = authenticate_request(request)
        if not user:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        from .models import UserAddress
        
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        
        # Validate required fields
        required_fields = ['address_type', 'street_address', 'city', 'state', 'zip_code']
        for field in required_fields:
            if not data.get(field, '').strip():
                return JsonResponse({'status': 'error', 'message': f'{field.replace("_", " ").title()} is required'}, status=400)
        
        # Validate address type
        valid_types = ['home', 'work', 'billing', 'shipping', 'other']
        if data['address_type'] not in valid_types:
            return JsonResponse({'status': 'error', 'message': f'Address type must be one of: {valid_types}'}, status=400)
        
        # If this is set as default, remove default from other addresses
        is_default = data.get('is_default', False)
        if is_default:
            UserAddress.objects.filter(user=user, is_default=True).update(is_default=False)
        
        # Create address
        address = UserAddress.objects.create(
            user=user,
            address_type=data['address_type'],
            street_address=data['street_address'].strip(),
            apartment_number=data.get('apartment_number', '').strip(),
            city=data['city'].strip(),
            state=data['state'].strip(),
            zip_code=data['zip_code'].strip(),
            country=data.get('country', 'United States').strip(),
            is_default=is_default
        )
        
        return JsonResponse({
            'status': 'success',
            'message': 'Address created successfully',
            'data': {
                'id': address.id,
                'address_type': address.address_type,
                'street_address': address.street_address,
                'apartment_number': address.apartment_number,
                'city': address.city,
                'state': address.state,
                'zip_code': address.zip_code,
                'country': address.country,
                'is_default': address.is_default,
                'created_at': address.created_at.isoformat(),
            }
        })


@method_decorator(csrf_exempt, name='dispatch')
class UserAddressDetailView(View):
    """Get, update, delete specific address"""
    
    def get(self, request, address_id):
        """Get specific address"""
        user = authenticate_request(request)
        if not user:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        from .models import UserAddress
        
        try:
            address = UserAddress.objects.get(id=address_id, user=user)
        except UserAddress.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Address not found'}, status=404)
        
        return JsonResponse({
            'status': 'success',
            'data': {
                'id': address.id,
                'address_type': address.address_type,
                'street_address': address.street_address,
                'apartment_number': address.apartment_number,
                'city': address.city,
                'state': address.state,
                'zip_code': address.zip_code,
                'country': address.country,
                'is_default': address.is_default,
                'created_at': address.created_at.isoformat(),
            }
        })
    
    def put(self, request, address_id):
        """Update specific address"""
        user = authenticate_request(request)
        if not user:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        from .models import UserAddress
        
        try:
            address = UserAddress.objects.get(id=address_id, user=user)
        except UserAddress.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Address not found'}, status=404)
        
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        
        # Update fields
        if 'address_type' in data:
            valid_types = ['home', 'work', 'billing', 'shipping', 'other']
            if data['address_type'] not in valid_types:
                return JsonResponse({'status': 'error', 'message': f'Address type must be one of: {valid_types}'}, status=400)
            address.address_type = data['address_type']
        
        if 'street_address' in data:
            address.street_address = data['street_address'].strip()
        if 'apartment_number' in data:
            address.apartment_number = data['apartment_number'].strip()
        if 'city' in data:
            address.city = data['city'].strip()
        if 'state' in data:
            address.state = data['state'].strip()
        if 'zip_code' in data:
            address.zip_code = data['zip_code'].strip()
        if 'country' in data:
            address.country = data['country'].strip()
        
        # Handle default status
        if 'is_default' in data and data['is_default']:
            # Remove default from other addresses
            UserAddress.objects.filter(user=user, is_default=True).update(is_default=False)
            address.is_default = True
        elif 'is_default' in data and not data['is_default']:
            address.is_default = False
        
        address.save()
        
        return JsonResponse({
            'status': 'success',
            'message': 'Address updated successfully',
            'data': {
                'id': address.id,
                'address_type': address.address_type,
                'street_address': address.street_address,
                'apartment_number': address.apartment_number,
                'city': address.city,
                'state': address.state,
                'zip_code': address.zip_code,
                'country': address.country,
                'is_default': address.is_default,
                'updated_at': address.updated_at.isoformat(),
            }
        })
    
    def delete(self, request, address_id):
        """Delete specific address"""
        user = authenticate_request(request)
        if not user:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        from .models import UserAddress
        
        try:
            address = UserAddress.objects.get(id=address_id, user=user)
        except UserAddress.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Address not found'}, status=404)
        
        address.delete()
        
        return JsonResponse({
            'status': 'success',
            'message': 'Address deleted successfully'
        })


@method_decorator(csrf_exempt, name='dispatch')
class SetDefaultAddressView(View):
    """Set an address as default"""
    
    def post(self, request, address_id):
        user = authenticate_request(request)
        if not user:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        from .models import UserAddress
        
        try:
            address = UserAddress.objects.get(id=address_id, user=user)
        except UserAddress.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Address not found'}, status=404)
        
        # Remove default from all other addresses
        UserAddress.objects.filter(user=user, is_default=True).update(is_default=False)
        
        # Set this address as default
        address.is_default = True
        address.save()
        
        return JsonResponse({
            'status': 'success',
            'message': 'Default address updated successfully'
        })
