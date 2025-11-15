import json
import random
import string
from decimal import Decimal
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from django.core.paginator import Paginator
from django.utils import timezone
from .models import Order, OrderItem, CustomerAddress, OrderOTP
from cart.models import Cart, CartItem
from users.models import UserAddress
from users.utils import authenticate_request, manager_required, parse_json_body
from .utils import save_invoice_pdf


def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))


def send_otp_email(email, otp, purpose="order verification"):
    """
    Send OTP via email
    TODO: Implement actual email sending using Django's email backend
    For now, just print to console
    """
    print("="*50)
    print(f"OTP EMAIL - {purpose.upper()}")
    print("="*50)
    print(f"To: {email}")
    print(f"Subject: Your OTP for {purpose}")
    print(f"OTP Code: {otp}")
    print(f"Valid for: 10 minutes")
    print("="*50)
    # TODO: Uncomment and configure when email is set up
    # from django.core.mail import send_mail
    # send_mail(
    #     subject=f'Your OTP for {purpose}',
    #     message=f'Your OTP is: {otp}\\n\\nThis OTP is valid for 10 minutes.',
    #     from_email='noreply@notedstore.com',
    #     recipient_list=[email],
    #     fail_silently=False,
    # )


def send_order_confirmation_email(email, order):
    """
    Send order confirmation email
    TODO: Implement actual email sending
    For now, just print to console
    """
    print("="*50)
    print("ORDER CONFIRMATION EMAIL")
    print("="*50)
    print(f"To: {email}")
    print(f"Subject: Order Confirmation - Order #{order.id}")
    print(f"Order ID: {order.id}")
    print(f"Status: {order.status}")
    print(f"Total Amount: ${order.total_amount}")
    print(f"Date: {order.created_at}")
    print("\\nOrder Items:")
    for item in order.items.all():
        print(f"  - {item.product.name} x {item.quantity} @ ${item.price} = ${item.total_price}")
    print(f"\\nShipping Address:")
    print(f"  {order.address.street_address}")
    print(f"  {order.address.city}, {order.address.state} {order.address.zip_code}")
    print(f"  {order.address.country}")
    print("="*50)
    # TODO: Uncomment and configure when email is set up
    # from django.core.mail import send_mail
    # send_mail(
    #     subject=f'Order Confirmation - Order #{order.id}',
    #     message=order_confirmation_message,
    #     from_email='noreply@notedstore.com',
    #     recipient_list=[email],
    #     fail_silently=False,
    # )


@method_decorator(csrf_exempt, name='dispatch')
class GenerateOrderOTPView(View):
    """POST: Generate OTP for order placement"""
    def post(self, request):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        
        address_id = data.get('address_id')
        if not address_id:
            return JsonResponse({
                'status': 'error',
                'message': 'Address ID is required'
            }, status=400)
        
        # Verify address exists and belongs to user
        try:
            user_address = UserAddress.objects.get(id=address_id, user=user)
        except UserAddress.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Address not found'
            }, status=404)
        
        # Check if cart has items
        try:
            cart = Cart.objects.prefetch_related('items__product').get(user=user)
            if not cart.items.exists():
                return JsonResponse({
                    'status': 'error',
                    'message': 'Cart is empty'
                }, status=400)
        except Cart.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Cart is empty'
            }, status=400)
        
        # Invalidate any previous OTPs for this user
        OrderOTP.objects.filter(user=user, is_used=False, is_verified=False).update(is_used=True)
        
        # Generate new OTP
        otp = generate_otp()
        
        # Create OTP record
        order_otp = OrderOTP.objects.create(
            user=user,
            otp=otp,
            address_id=address_id
        )
        
        # Send OTP via email (currently prints to console)
        send_otp_email(user.email, otp, "order verification")
        
        return JsonResponse({
            'status': 'success',
            'message': 'OTP sent to your email',
            'data': {
                'otp_id': order_otp.id,
                'expires_in': 600  # 10 minutes in seconds
            }
        })


@method_decorator(csrf_exempt, name='dispatch')
class VerifyOrderOTPView(View):
    """POST: Verify OTP before placing order"""
    def post(self, request):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        
        otp = data.get('otp')
        if not otp:
            return JsonResponse({
                'status': 'error',
                'message': 'OTP is required'
            }, status=400)
        
        # Find the most recent valid OTP for this user
        try:
            order_otp = OrderOTP.objects.filter(
                user=user,
                otp=otp,
                is_used=False,
                is_verified=False
            ).latest('created_at')
            
            if not order_otp.is_valid():
                return JsonResponse({
                    'status': 'error',
                    'message': 'OTP has expired. Please request a new one.'
                }, status=400)
            
            # Mark OTP as verified
            order_otp.is_verified = True
            order_otp.save()
            
            return JsonResponse({
                'status': 'success',
                'message': 'OTP verified successfully',
                'data': {
                    'address_id': order_otp.address_id
                }
            })
            
        except OrderOTP.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid OTP'
            }, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class PlaceOrderView(View):
    """POST: place an order from cart (requires verified OTP)"""
    def post(self, request):
        # Authenticate user
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        
        address_id = data.get('address_id')
        if not address_id:
            return JsonResponse({
                'status': 'error',
                'message': 'Address ID is required'
            }, status=400)
        
        # Verify that user has a verified OTP for this address
        try:
            order_otp = OrderOTP.objects.filter(
                user=user,
                address_id=address_id,
                is_verified=True,
                is_used=False
            ).latest('created_at')
            
            # Mark OTP as used
            order_otp.is_used = True
            order_otp.save()
            
        except OrderOTP.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'OTP verification required. Please verify OTP before placing order.'
            }, status=403)
        
        # Get address
        try:
            user_address = UserAddress.objects.get(id=address_id, user=user)
            # Create or get corresponding CustomerAddress
            address, created = CustomerAddress.objects.get_or_create(
                user=user,
                street_address=user_address.street_address,
                city=user_address.city,
                state=user_address.state,
                zip_code=user_address.zip_code,
                country=user_address.country,
                defaults={'is_default': user_address.is_default}
            )
        except UserAddress.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Address not found'
            }, status=404)
        try:
            cart = Cart.objects.prefetch_related('items__product').get(user=user)
        except Cart.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Cart is empty'
            }, status=400)
        if not cart.items.exists():
            return JsonResponse({
                'status': 'error',
                'message': 'Cart is empty'
            }, status=400)
        try:
            with transaction.atomic():
                total_amount = Decimal('0.00')
                order_items_data = []
                for cart_item in cart.items.select_related('product').prefetch_related('product__variants').all():
                    product = cart_item.product
                    
                    # Check stock - use variant stock if size is specified
                    if cart_item.size:
                        try:
                            variant = product.variants.get(size=cart_item.size)
                            available_stock = variant.stock
                        except product.variants.model.DoesNotExist:
                            return JsonResponse({
                                'status': 'error',
                                'message': f'Size {cart_item.size} not available for {product.name}'
                            }, status=400)
                    else:
                        available_stock = product.stock
                        variant = None
                    
                    if available_stock < cart_item.quantity:
                        return JsonResponse({
                            'status': 'error',
                            'message': f'Insufficient stock for {product.name}. Available: {available_stock}'
                        }, status=400)
                    
                    item_total = product.discounted_price * cart_item.quantity
                    total_amount += item_total
                    order_items_data.append({
                        'product': product,
                        'variant': variant,
                        'quantity': cart_item.quantity,
                        'price': product.discounted_price,
                        'size': cart_item.size
                    })
                order = Order.objects.create(
                    user=user,
                    address=address,
                    total_amount=total_amount,
                    status='placed'
                )
                for item_data in order_items_data:
                    OrderItem.objects.create(
                        order=order,
                        product=item_data['product'],
                        quantity=item_data['quantity'],
                        price=item_data['price']
                    )
                    # Decrease stock - use variant stock if size was specified
                    if item_data['variant']:
                        item_data['variant'].stock -= item_data['quantity']
                        item_data['variant'].save()
                    else:
                        item_data['product'].stock -= item_data['quantity']
                        item_data['product'].save()
                cart.items.all().delete()
                
                # Generate and save invoice PDF
                try:
                    invoice_path = save_invoice_pdf(order)
                    order.invoice_pdf = invoice_path
                    order.save()
                    print(f"✓ Invoice PDF generated: {invoice_path}")
                except Exception as e:
                    print(f"⚠ Warning: Failed to generate invoice PDF: {str(e)}")
                
                # Send order confirmation email (currently prints to console)
                send_order_confirmation_email(user.email, order)
                
                items_data = []
                for item in order.items.select_related('product').all():
                    items_data.append({
                        'id': item.id,
                        'product': {
                            'id': item.product.id,
                            'name': item.product.name,
                            'price': str(item.price)
                        },
                        'quantity': item.quantity,
                        'price': str(item.price),
                        'total_price': str(item.total_price)
                    })
                return JsonResponse({
                    'status': 'success',
                    'message': 'Order placed successfully',
                    'data': {
                        'order': {
                            'id': order.id,
                            'status': order.status,
                            'total_amount': str(order.total_amount),
                            'invoice_pdf': f"/media/{order.invoice_pdf}" if order.invoice_pdf else None,
                            'address': {
                                'id': address.id,
                                'street_address': address.street_address,
                                'city': address.city,
                                'state': address.state,
                                'zip_code': address.zip_code,
                                'country': address.country
                            },
                            'items': items_data,
                            'created_at': order.created_at.isoformat()
                        }
                    }
                }, status=201)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f'Failed to place order: {str(e)}'
            }, status=400)


class CustomerOrdersView(View):
    """GET: list customer's orders"""
    def get(self, request):
        # Authenticate user
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        page = int(request.GET.get('page', 1))
        limit = int(request.GET.get('limit', 10))
        orders = Order.objects.filter(user=user).prefetch_related(
            'items__product', 'address'
        ).order_by('-created_at')
        paginator = Paginator(orders, limit)
        try:
            page_obj = paginator.page(page)
        except:
            page_obj = paginator.page(1)
        orders_data = []
        for order in page_obj:
            items_data = []
            for item in order.items.all():
                items_data.append({
                    'id': item.id,
                    'product': {
                        'id': item.product.id,
                        'name': item.product.name,
                    },
                    'quantity': item.quantity,
                    'price': str(item.price),
                    'total_price': str(item.total_price)
                })
            orders_data.append({
                'id': order.id,
                'status': order.status,
                'total_amount': str(order.total_amount),
                'invoice_pdf': f"/media/{order.invoice_pdf}" if order.invoice_pdf else None,
                'created_at': order.created_at.isoformat(),
                'updated_at': order.updated_at.isoformat(),
                'address': {
                    'street': order.address.street_address if order.address else '',
                    'city': order.address.city if order.address else '',
                    'state': order.address.state if order.address else '',
                    'pincode': order.address.zip_code if order.address else '',
                } if order.address else None,
                'items': items_data
            })
        return JsonResponse({
            'status': 'success',
            'data': {
                'orders': orders_data,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total_pages': paginator.num_pages,
                    'total_items': paginator.count,
                    'has_next': page_obj.has_next(),
                    'has_previous': page_obj.has_previous()
                }
            }
        })


class AdminOrdersView(View):
    """GET: list all orders (manager only)"""
    def get(self, request):
        # Authenticate user
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        # Check if user is manager
        if not user.is_superuser and not user.role == 'manager':
            return JsonResponse({'status': 'error', 'message': 'Manager access required'}, status=403)
        page = int(request.GET.get('page', 1))
        limit = int(request.GET.get('limit', 10))
        status_filter = request.GET.get('status')
        orders = Order.objects.prefetch_related(
            'items__product', 'address', 'user'
        ).select_related('user').order_by('-created_at')
        if status_filter:
            orders = orders.filter(status=status_filter)
        paginator = Paginator(orders, limit)
        try:
            page_obj = paginator.page(page)
        except:
            page_obj = paginator.page(1)
        orders_data = []
        for order in page_obj:
            items_data = []
            for item in order.items.all():
                items_data.append({
                    'id': item.id,
                    'product': {
                        'id': item.product.id,
                        'name': item.product.name,
                    },
                    'quantity': item.quantity,
                    'price': str(item.price),
                    'total_price': str(item.total_price)
                })
            orders_data.append({
                'id': order.id,
                'user': {
                    'id': order.user.id,
                    'username': order.user.username,
                    'email': order.user.email
                },
                'status': order.status,
                'total_amount': str(order.total_amount),
                'address': {
                    'id': order.address.id if order.address else None,
                    'street_address': order.address.street_address if order.address else None,
                    'city': order.address.city if order.address else None,
                    'state': order.address.state if order.address else None,
                    'zip_code': order.address.zip_code if order.address else None,
                } if order.address else None,
                'items': items_data,
                'created_at': order.created_at.isoformat(),
                'updated_at': order.updated_at.isoformat()
            })
        return JsonResponse({
            'status': 'success',
            'data': {
                'orders': orders_data,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total_pages': paginator.num_pages,
                    'total_items': paginator.count,
                    'has_next': page_obj.has_next(),
                    'has_previous': page_obj.has_previous()
                }
            }
        })


@method_decorator(csrf_exempt, name='dispatch')
class OrderStatusView(View):
    """PATCH: update order status (manager only)"""
    def patch(self, request, order_id):
        # Authenticate user
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        # Check if user is manager
        if not user.is_superuser and not user.role == 'manager':
            return JsonResponse({'status': 'error', 'message': 'Manager access required'}, status=403)
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        status = data.get('status')
        if not status:
            return JsonResponse({
                'status': 'error',
                'message': 'status is required'
            }, status=400)
        valid_statuses = ['placed', 'confirmed', 'packed', 'dispatched', 'delivered', 'cancelled']
        if status not in valid_statuses:
            return JsonResponse({
                'status': 'error',
                'message': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'
            }, status=400)
        try:
            order = Order.objects.get(id=order_id)
        except Order.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Order not found'
            }, status=404)
        order.status = status
        order.save()
        return JsonResponse({
            'status': 'success',
            'message': 'Order status updated successfully',
            'data': {
                'id': order.id,
                'status': order.status,
                'updated_at': order.updated_at.isoformat()
            }
        })


class AdminDashboardView(View):
    """GET: admin dashboard summary (manager only)"""
    def get(self, request):
        # Authenticate user
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        # Check if user is manager
        if not user.is_superuser and not user.role == 'manager':
            return JsonResponse({'status': 'error', 'message': 'Manager access required'}, status=403)
        from django.contrib.auth import get_user_model
        from django.db.models import Count, Sum, Q
        from products.models import Product
        User = get_user_model()
        total_users = User.objects.count()
        total_orders = Order.objects.count()
        orders_by_status = {}
        for status_choice in Order.STATUS_CHOICES:
            status_code = status_choice[0]
            count = Order.objects.filter(status=status_code).count()
            orders_by_status[status_code] = count
        top_products = OrderItem.objects.values(
            'product__name'
        ).annotate(
            sold=Sum('quantity')
        ).order_by('-sold')[:10]
        top_products_list = [
            {'name': item['product__name'], 'sold': item['sold']}
            for item in top_products
        ]
        return JsonResponse({
            'status': 'success',
            'data': {
                'total_users': total_users,
                'total_orders': total_orders,
                'orders_by_status': orders_by_status,
                'top_products': top_products_list
            }
        })
