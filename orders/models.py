from django.db import models
from django.core.validators import MinValueValidator


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
        ('placed', 'Placed'),
        ('confirmed', 'Confirmed'),
        ('packed', 'Packed'),
        ('dispatched', 'Dispatched'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
    ]
    
    user = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='orders')
    address = models.ForeignKey(CustomerAddress, on_delete=models.SET_NULL, null=True, related_name='orders')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='placed')
    total_amount = models.DecimalField(max_digits=10, decimal_places=2, validators=[MinValueValidator(0)])
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Track when stock was reduced
    stock_reduced = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-created_at']
    
    def save(self, *args, **kwargs):
        # Handle stock management when status changes
        if self.pk:  # Only for existing orders (updates)
            old_instance = Order.objects.get(pk=self.pk)
            old_status = old_instance.status
            new_status = self.status
            
            # If order is being confirmed and stock hasn't been reduced yet
            if old_status == 'placed' and new_status == 'confirmed' and not self.stock_reduced:
                self._reduce_stock()
                self.stock_reduced = True
                
            # If order is being cancelled and stock was previously reduced
            elif new_status == 'cancelled' and self.stock_reduced:
                self._restore_stock()
                self.stock_reduced = False
                
        super().save(*args, **kwargs)
    
    def _reduce_stock(self):
        """Reduce product stock when order is confirmed"""
        from products.models import Product
        for item in self.items.all():
            product = item.product
            product.stock = max(0, product.stock - item.quantity)
            product.save()
    
    def _restore_stock(self):
        """Restore product stock when order is cancelled"""
        for item in self.items.all():
            product = item.product
            product.stock += item.quantity
            product.save()
    
    def __str__(self):
        return f"Order #{self.id} by {self.user.username} - {self.status}"


class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey('products.Product', on_delete=models.CASCADE)
    quantity = models.IntegerField(validators=[MinValueValidator(1)])
    price = models.DecimalField(max_digits=10, decimal_places=2, validators=[MinValueValidator(0)])
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.quantity}x {self.product.name} in Order #{self.order.id}"
    
    @property
    def total_price(self):
        return self.price * self.quantity
