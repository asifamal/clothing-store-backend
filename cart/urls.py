from django.urls import path
from .views import CartView, CartAddView, CartItemView, TestAuthView

urlpatterns = [
    path('test-auth/', TestAuthView.as_view(), name='test_auth'),
    path('', CartView.as_view(), name='get_cart'),
    path('add/', CartAddView.as_view(), name='add_to_cart'),
    path('item/<int:item_id>/', CartItemView.as_view(), name='update_cart_item'),
]

