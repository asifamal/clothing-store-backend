import json
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from .models import Cart, CartItem
from products.models import Product
from users.utils import authenticate_request, parse_json_body


class TestAuthView(View):
    """Test authentication"""
    def get(self, request):
        # Log what we receive
        auth_header = request.META.get('HTTP_AUTHORIZATION', 'No auth header')
        print(f"Auth header received: {auth_header}")
        
        user = authenticate_request(request)
        if not user:
            return JsonResponse({
                'status': 'error', 
                'message': 'Authentication required',
                'debug_info': {
                    'auth_header_present': 'HTTP_AUTHORIZATION' in request.META,
                    'auth_header_value': auth_header[:50] if auth_header != 'No auth header' else auth_header
                }
            }, status=401)
        return JsonResponse({
            'status': 'success', 
            'message': f'Authenticated as {user.username}',
            'user_id': user.id
        })


@method_decorator(csrf_exempt, name='dispatch')
class CartView(View):
    """GET: get user's cart"""
    def get(self, request):
        user = authenticate_request(request)
        if not user:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        cart, created = Cart.objects.get_or_create(user=user)
        items_data = []
        for item in cart.items.select_related('product', 'product__category').all():
            items_data.append({
                'id': item.id,
                'product': {
                    'id': item.product.id,
                    'name': item.product.name,
                    'price': str(item.product.price),
                    'discounted_price': str(item.product.discounted_price),
                    'image': item.product.image.url if item.product.image else None,
                },
                'quantity': item.quantity,
                'total_price': str(item.total_price)
            })
        return JsonResponse({
            'status': 'success',
            'data': {
                'cart': {
                    'id': cart.id,
                    'items': items_data,
                    'total_price': str(cart.total_price)
                }
            }
        })


@method_decorator(csrf_exempt, name='dispatch')
class CartAddView(View):
    """POST: add item to cart"""
    def post(self, request):
        user = authenticate_request(request)
        if not user:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        product_id = data.get('product_id')
        quantity = data.get('quantity', 1)
        if not product_id:
            return JsonResponse({
                'status': 'error',
                'message': 'product_id is required'
            }, status=400)
        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Product not found'
            }, status=404)
        try:
            quantity = int(quantity)
            if quantity < 1:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Quantity must be at least 1'
                }, status=400)
        except (ValueError, TypeError):
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid quantity value'
            }, status=400)
        if product.stock < quantity:
            return JsonResponse({
                'status': 'error',
                'message': f'Insufficient stock. Available: {product.stock}'
            }, status=400)
        cart, created = Cart.objects.get_or_create(user=user)
        cart_item, created = CartItem.objects.get_or_create(
            cart=cart,
            product=product,
            defaults={'quantity': quantity}
        )
        if not created:
            cart_item.quantity += quantity
            if cart_item.quantity > product.stock:
                return JsonResponse({
                    'status': 'error',
                    'message': f'Insufficient stock. Available: {product.stock}'
                }, status=400)
            cart_item.save()
        return JsonResponse({
            'status': 'success',
            'message': 'Item added to cart',
            'data': {
                'id': cart_item.id,
                'product': {
                    'id': product.id,
                    'name': product.name,
                },
                'quantity': cart_item.quantity,
                'total_price': str(cart_item.total_price)
            }
        })


@method_decorator(csrf_exempt, name='dispatch')
class CartItemView(View):
    """PUT/DELETE: update or remove specific cart item"""
    def put(self, request, item_id):
        user = authenticate_request(request)
        if not user:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        quantity = data.get('quantity')
        if not quantity:
            return JsonResponse({
                'status': 'error',
                'message': 'quantity is required'
            }, status=400)
        try:
            quantity = int(quantity)
            if quantity < 1:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Quantity must be at least 1'
                }, status=400)
        except (ValueError, TypeError):
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid quantity value'
            }, status=400)
        try:
            cart_item = CartItem.objects.select_related('cart', 'product').get(
                id=item_id,
                cart__user=user
            )
        except CartItem.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Cart item not found'
            }, status=404)
        if cart_item.product.stock < quantity:
            return JsonResponse({
                'status': 'error',
                'message': f'Insufficient stock. Available: {cart_item.product.stock}'
            }, status=400)
        cart_item.quantity = quantity
        cart_item.save()
        return JsonResponse({
            'status': 'success',
            'message': 'Cart item updated',
            'data': {
                'id': cart_item.id,
                'quantity': cart_item.quantity,
                'total_price': str(cart_item.total_price)
            }
        })
    def delete(self, request, item_id):
        user = authenticate_request(request)
        if not user:
            return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=401)
        
        try:
            cart_item = CartItem.objects.get(
                id=item_id,
                cart__user=user
            )
            cart_item.delete()
            return JsonResponse({
                'status': 'success',
                'message': 'Item removed from cart'
            })
        except CartItem.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Cart item not found'
            }, status=404)
