from django.contrib import admin
from .models import Order, OrderItem, CustomerAddress, CourierPartner


@admin.register(CourierPartner)
class CourierPartnerAdmin(admin.ModelAdmin):
    list_display = ['name', 'contact_number', 'email', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'contact_number', 'email']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(CustomerAddress)
class CustomerAddressAdmin(admin.ModelAdmin):
    list_display = ['user', 'street_address', 'city', 'state', 'is_default']
    list_filter = ['is_default', 'country']


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'status', 'total_amount', 'created_at']
    list_filter = ['status', 'created_at']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    list_display = ['order', 'product', 'quantity', 'price']
    list_filter = ['created_at']
