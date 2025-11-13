from django.urls import path
from .views import ProductsView, ProductAddView, ProductDetailView, CategoriesView, FeaturedProductsView, CategoryAttributesView

urlpatterns = [
    path('', ProductsView.as_view(), name='list_products'),
    path('featured/', FeaturedProductsView.as_view(), name='featured_products'),
    path('add/', ProductAddView.as_view(), name='add_product'),
    path('<int:product_id>/', ProductDetailView.as_view(), name='update_product'),
    path('<int:product_id>/delete/', ProductDetailView.as_view(), name='delete_product'),
    path('categories/', CategoriesView.as_view(), name='list_categories'),
    path('categories/<int:category_id>/attributes/', CategoryAttributesView.as_view(), name='public_category_attributes'),
]

