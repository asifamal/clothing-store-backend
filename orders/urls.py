from django.urls import path
from .views import PlaceOrderView, CustomerOrdersView, AdminOrdersView, OrderStatusView, AdminDashboardView

urlpatterns = [
    path('place/', PlaceOrderView.as_view(), name='place_order'),
    path('', CustomerOrdersView.as_view(), name='list_orders'),
    path('admin/', AdminOrdersView.as_view(), name='list_all_orders'),
    path('admin/<int:order_id>/status/', OrderStatusView.as_view(), name='update_order_status'),
    path('admin/dashboard/', AdminDashboardView.as_view(), name='admin_dashboard'),
]

