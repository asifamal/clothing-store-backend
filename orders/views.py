import json
from decimal import Decimal
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from django.core.paginator import Paginator
from .models import Order, OrderItem, CustomerAddress
from cart.models import Cart, CartItem
from users.models import UserAddress
from users.utils import authenticate_request, manager_required, parse_json_body


@method_decorator(csrf_exempt, name='dispatch')
class PlaceOrderView(View):
    """POST: place an order from cart"""
    def post(self, request):
        # Authenticate user
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        address_id = data.get('address_id')
        if address_id:
            try:
                user_address = UserAddress.objects.get(id=address_id, user=user)
                # Create or get corresponding CustomerAddress
                address, created = CustomerAddress.objects.get_or_create(
                    user=user,
                    street_address=user_address.street,
                    city=user_address.city,
                    state=user_address.state,
                    zip_code=user_address.pincode,
                    country=user_address.country,
                    defaults={'is_default': user_address.is_default}
                )
            except UserAddress.DoesNotExist:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Address not found'
                }, status=404)
        else:
            street_address = data.get('street_address')
            city = data.get('city')
            state = data.get('state')
            zip_code = data.get('zip_code')
            country = data.get('country', 'USA')
            if not all([street_address, city, state, zip_code]):
                return JsonResponse({
                    'status': 'error',
                    'message': 'Address details are required'
                }, status=400)
            address = CustomerAddress.objects.create(
                user=user,
                street_address=street_address,
                city=city,
                state=state,
                zip_code=zip_code,
                country=country
            )
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
                for cart_item in cart.items.all():
                    product = cart_item.product
                    if product.stock < cart_item.quantity:
                        return JsonResponse({
                            'status': 'error',
                            'message': f'Insufficient stock for {product.name}. Available: {product.stock}'
                        }, status=400)
                    item_total = product.discounted_price * cart_item.quantity
                    total_amount += item_total
                    order_items_data.append({
                        'product': product,
                        'quantity': cart_item.quantity,
                        'price': product.discounted_price
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
                    item_data['product'].stock -= item_data['quantity']
                    item_data['product'].save()
                cart.items.all().delete()
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
