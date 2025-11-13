import json
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator
from django.db.models import Q, Sum
from .models import Product, Category
from users.utils import jwt_required, manager_required, parse_json_body


class ProductsView(View):
    """GET: list all products with pagination and filtering"""
    def get(self, request):
        page = int(request.GET.get('page', 1))
        limit = int(request.GET.get('limit', 10))
        category_id = request.GET.get('category_id')
        search = request.GET.get('search')
        min_price = request.GET.get('min_price')
        max_price = request.GET.get('max_price')
        
        products = Product.objects.select_related('category').prefetch_related('attributes__category_attribute').all()
        
        # Category filtering
        if category_id:
            products = products.filter(category_id=category_id)
        
        # Search filtering
        if search:
            products = products.filter(
                Q(name__icontains=search) | Q(description__icontains=search)
            )
        
        # Price filtering
        if min_price:
            try:
                min_price_val = float(min_price)
                products = products.filter(price__gte=min_price_val)
            except (ValueError, TypeError):
                pass  # Invalid price, ignore filter
        
        if max_price:
            try:
                max_price_val = float(max_price)
                products = products.filter(price__lte=max_price_val)
            except (ValueError, TypeError):
                pass  # Invalid price, ignore filter
        
        # Attribute filtering (e.g., ?attr_1=Long Sleeve&attr_2=Cotton&attr_3=10-50)
        attribute_filters = {}
        for key, value in request.GET.items():
            if key.startswith('attr_') and value.strip():  # Only process non-empty values
                attr_id = key.replace('attr_', '')
                try:
                    attr_id = int(attr_id)
                    attribute_filters[attr_id] = value.strip()
                except ValueError:
                    continue
        
        # Apply attribute filters
        for attr_id, attr_value in attribute_filters.items():
            from .models import CategoryAttribute
            try:
                attr_obj = CategoryAttribute.objects.get(id=attr_id)
                
                if attr_obj.attribute_type == 'number' and '-' in attr_value:
                    # Handle number range filtering (e.g., "10-50")
                    try:
                        min_val, max_val = attr_value.split('-')
                        min_val = float(min_val) if min_val else 0
                        max_val = float(max_val) if max_val != '999999' else 999999999
                        
                        # Filter products where the attribute value is within the range
                        products = products.filter(
                            attributes__category_attribute_id=attr_id,
                            attributes__value__regex=r'^[0-9]+(\.[0-9]+)?$'  # Ensure it's a number
                        ).extra(
                            where=[
                                "CAST(products_productattribute.value AS DECIMAL(10,2)) BETWEEN %s AND %s"
                            ],
                            params=[min_val, max_val]
                        )
                    except (ValueError, IndexError):
                        # If range parsing fails, treat as regular text search
                        products = products.filter(
                            attributes__category_attribute_id=attr_id,
                            attributes__value__icontains=attr_value
                        )
                else:
                    # Regular text/select filtering with case-insensitive search
                    products = products.filter(
                        attributes__category_attribute_id=attr_id,
                        attributes__value__icontains=attr_value
                    )
            except CategoryAttribute.DoesNotExist:
                continue
        
        paginator = Paginator(products, limit)
        try:
            page_obj = paginator.page(page)
        except:
            page_obj = paginator.page(1)
        
        products_data = []
        for product in page_obj:
            # Include product attributes in response
            product_attributes = []
            for prod_attr in product.attributes.all():
                product_attributes.append({
                    'id': prod_attr.category_attribute.id,
                    'name': prod_attr.category_attribute.name,
                    'value': prod_attr.value,
                    'field_type': prod_attr.category_attribute.attribute_type
                })
            
            products_data.append({
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': str(product.price),
                'stock': product.stock,
                'category': {
                    'id': product.category.id,
                    'name': product.category.name
                },
                'image': product.image.url if product.image else None,
                'attributes': product_attributes,
                'created_at': product.created_at.isoformat(),
            })
        
        return JsonResponse({
            'status': 'success',
            'data': {
                'products': products_data,
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


class FeaturedProductsView(View):
    """GET: list featured/top-selling products"""
    def get(self, request):
        try:
            limit = int(request.GET.get('limit', 8))
        except (ValueError, TypeError):
            limit = 8
        products = Product.objects.select_related('category').annotate(
            sold=Sum('orderitem__quantity')
        ).order_by('-sold', '-created_at')[:limit]
        products_data = []
        for product in products:
            products_data.append({
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': str(product.price),
                'stock': product.stock,
                'category': {
                    'id': product.category.id,
                    'name': product.category.name
                },
                'image': product.image.url if product.image else None,
                'sold': int(product.sold or 0),
                'created_at': product.created_at.isoformat(),
            })
        return JsonResponse({
            'status': 'success',
            'data': {
                'products': products_data
            }
        })


@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(jwt_required, name='dispatch')
@method_decorator(manager_required, name='dispatch')
class ProductAddView(View):
    """POST: add a new product (manager only)"""
    def post(self, request):
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        name = data.get('name')
        description = data.get('description', '')
        price = data.get('price')
        stock = data.get('stock', 0)
        category_id = data.get('category_id')
        if not name or not price or not category_id:
            return JsonResponse({
                'status': 'error',
                'message': 'Name, price, and category_id are required'
            }, status=400)
        try:
            category = Category.objects.get(id=category_id)
        except Category.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Category not found'
            }, status=404)
        try:
            price = float(price)
            stock = int(stock)
            if price < 0 or stock < 0:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Price and stock must be non-negative'
                }, status=400)
        except (ValueError, TypeError):
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid price or stock value'
            }, status=400)
        image = request.FILES.get('image')
        try:
            product = Product.objects.create(
                name=name,
                description=description,
                price=price,
                stock=stock,
                category=category,
                image=image
            )
            return JsonResponse({
                'status': 'success',
                'message': 'Product created successfully',
                'data': {
                    'id': product.id,
                    'name': product.name,
                    'description': product.description,
                    'price': str(product.price),
                    'stock': product.stock,
                    'category': {
                        'id': product.category.id,
                        'name': product.category.name
                    },
                    'image': product.image.url if product.image else None,
                    'created_at': product.created_at.isoformat(),
                }
            }, status=201)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f'Failed to create product: {str(e)}'
            }, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class ProductDetailView(View):
    """GET/PUT/DELETE for product by id"""
    def get(self, request, product_id):
        """Public GET endpoint to fetch product details"""
        try:
            product = Product.objects.prefetch_related('variants', 'attributes__category_attribute').get(id=product_id)
            
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
                    'name': attr.category_attribute.name,
                    'value': attr.value,
                })
            
            return JsonResponse({
                'status': 'success',
                'data': {
                    'id': product.id,
                    'name': product.name,
                    'description': product.description,
                    'price': str(product.price),
                    'stock': product.stock,
                    'category': {
                        'id': product.category.id,
                        'name': product.category.name
                    } if product.category else None,
                    'image': product.image.url if product.image else None,
                    'variants': variants_data,
                    'attributes': attributes_data,
                    'created_at': product.created_at.isoformat(),
                    'updated_at': product.updated_at.isoformat(),
                }
            })
        except Product.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Product not found'
            }, status=404)
    
    @method_decorator(jwt_required)
    @method_decorator(manager_required)
    def put(self, request, product_id):
        data, error_response = parse_json_body(request)
        if error_response:
            return error_response
        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Product not found'
            }, status=404)
        if 'name' in data:
            product.name = data['name']
        if 'description' in data:
            product.description = data['description']
        if 'price' in data:
            try:
                price = float(data['price'])
                if price < 0:
                    return JsonResponse({
                        'status': 'error',
                        'message': 'Price must be non-negative'
                    }, status=400)
                product.price = price
            except (ValueError, TypeError):
                return JsonResponse({
                    'status': 'error',
                    'message': 'Invalid price value'
                }, status=400)
        if 'stock' in data:
            try:
                stock = int(data['stock'])
                if stock < 0:
                    return JsonResponse({
                        'status': 'error',
                        'message': 'Stock must be non-negative'
                    }, status=400)
                product.stock = stock
            except (ValueError, TypeError):
                return JsonResponse({
                    'status': 'error',
                    'message': 'Invalid stock value'
                }, status=400)
        if 'category_id' in data:
            try:
                category = Category.objects.get(id=data['category_id'])
                product.category = category
            except Category.DoesNotExist:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Category not found'
                }, status=404)
        if 'image' in request.FILES:
            product.image = request.FILES['image']
        product.save()
        return JsonResponse({
            'status': 'success',
            'message': 'Product updated successfully',
            'data': {
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': str(product.price),
                'stock': product.stock,
                'category': {
                    'id': product.category.id,
                    'name': product.category.name
                },
                'image': product.image.url if product.image else None,
                'updated_at': product.updated_at.isoformat(),
            }
        })
    
    @method_decorator(jwt_required)
    @method_decorator(manager_required)
    def delete(self, request, product_id):
        try:
            product = Product.objects.get(id=product_id)
            product.delete()
            return JsonResponse({
                'status': 'success',
                'message': 'Product deleted successfully'
            })
        except Product.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Product not found'
            }, status=404)


class CategoriesView(View):
    """GET: list all categories"""
    def get(self, request):
        categories = Category.objects.all()
        categories_data = []
        for category in categories:
            categories_data.append({
                'id': category.id,
                'name': category.name,
                'description': category.description,
                'created_at': category.created_at.isoformat(),
            })
        return JsonResponse({
            'status': 'success',
            'data': {
                'categories': categories_data
            }
        })


class CategoryAttributesView(View):
    """GET: public endpoint to get category attributes for filtering"""
    def get(self, request, category_id):
        try:
            from .models import CategoryAttribute, CategoryAttributeOption
            
            # Check if category exists
            if not Category.objects.filter(id=category_id).exists():
                return JsonResponse({'status': 'error', 'message': 'Category not found'}, status=404)
            
            attributes = CategoryAttribute.objects.filter(category_id=category_id).prefetch_related('options')
            attributes_data = []
            
            for attr in attributes:
                attr_data = {
                    'id': attr.id,
                    'name': attr.name,
                    'field_type': attr.attribute_type,
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
