from django.db import models
from django.core.validators import MinValueValidator
from django.utils import timezone
from datetime import timedelta


class CourierPartner(models.Model):
    """Store courier partner information"""
    name = models.CharField(max_length=100, unique=True)
    tracking_url = models.URLField(blank=True, null=True, help_text="URL template for tracking (use {awb} as placeholder)")
    contact_number = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
        verbose_name = 'Courier Partner'
        verbose_name_plural = 'Courier Partners'
    
    def __str__(self):
        return self.name


class OrderOTP(models.Model):
    """Store OTP for order verification"""
    user = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='order_otps')
    otp = models.CharField(max_length=6)
    address_id = models.IntegerField()
    is_verified = models.BooleanField(default=False)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=10)
        super().save(*args, **kwargs)
    
    def is_valid(self):
        """Check if OTP is still valid"""
        return not self.is_used and not self.is_verified and timezone.now() < self.expires_at
    
    def __str__(self):
        return f"OTP for {self.user.username} - {self.otp}"
    
    class Meta:
        ordering = ['-created_at']


class CustomerAddress(models.Model):
    user = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='addresses')
    street_address = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    zip_code = models.CharField(max_length=20)
    country = models.CharField(max_length=100, default='USA')
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name_plural = 'Customer Addresses'
    
    def __str__(self):
        return f"{self.street_address}, {self.city}, {self.state} {self.zip_code}"


class Order(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending Confirmation'),
        ('confirmed', 'Confirmed'),
        ('dispatched', 'Dispatched'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
    ]
    
    user = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='orders')
    address = models.ForeignKey(CustomerAddress, on_delete=models.SET_NULL, null=True, related_name='orders')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    total_amount = models.DecimalField(max_digits=10, decimal_places=2, validators=[MinValueValidator(0)])
    invoice_pdf = models.CharField(max_length=500, blank=True, null=True)  # Path to invoice PDF
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Track when stock was reduced
    stock_reduced = models.BooleanField(default=False)
    
    # Shipping details
    awb_number = models.CharField(max_length=100, blank=True, null=True)  # Air Waybill number
    courier_partner = models.CharField(max_length=100, blank=True, null=True)
    contact_phone = models.CharField(max_length=17, blank=True, null=True)  # Contact number for delivery
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Order #{self.id} by {self.user.username} - {self.status}"


class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey('products.Product', on_delete=models.CASCADE)
    quantity = models.IntegerField(validators=[MinValueValidator(1)])
    price = models.DecimalField(max_digits=10, decimal_places=2, validators=[MinValueValidator(0)])
    size = models.CharField(max_length=10, blank=True, null=True)  # For product variants
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        size_str = f" (Size: {self.size})" if self.size else ""
        return f"{self.quantity}x {self.product.name}{size_str} in Order #{self.order.id}"
    
    @property
    def total_price(self):
        return self.price * self.quantity
