from django.db import models
from django.core.validators import MinValueValidator


class Cart(models.Model):
    user = models.OneToOneField('users.User', on_delete=models.CASCADE, related_name='cart')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Cart for {self.user.username}"
    
    @property
    def total_price(self):
        return sum(item.total_price for item in self.items.all())


class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey('products.Product', on_delete=models.CASCADE)
    quantity = models.IntegerField(validators=[MinValueValidator(1)], default=1)
    size = models.CharField(max_length=10, blank=True, null=True)  # For product variants
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['cart', 'product', 'size']
    
    def __str__(self):
        size_str = f" (Size: {self.size})" if self.size else ""
        return f"{self.quantity}x {self.product.name}{size_str} in {self.cart.user.username}'s cart"
    
    @property
    def total_price(self):
        return self.product.price * self.quantity
