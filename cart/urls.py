from django.urls import path
from .views import CartView, CartAddView, CartItemView

urlpatterns = [
    path('', CartView.as_view(), name='get_cart'),
    path('add/', CartAddView.as_view(), name='add_to_cart'),
    path('<int:item_id>/', CartItemView.as_view(), name='update_cart_item'),
    path('<int:item_id>/delete/', CartItemView.as_view(), name='remove_from_cart'),
]

