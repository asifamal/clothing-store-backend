from django.urls import path
from . import views

urlpatterns = [
    path('test-auth/', views.TestAuthView.as_view(), name='test_auth'),
    path('', views.CartView.as_view(), name='cart'),
    path('add/', views.CartAddView.as_view(), name='cart_add'),
    path('item/<int:item_id>/', views.CartItemView.as_view(), name='cart_item'),
]