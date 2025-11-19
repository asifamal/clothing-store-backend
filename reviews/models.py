from django.db import models
from django.conf import settings
from products.models import Product
from orders.models import OrderItem
from django.core.validators import MinValueValidator, MaxValueValidator


class Review(models.Model):
    """Product review model with rating and comments"""
    
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='reviews')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='reviews')
    order_item = models.OneToOneField(OrderItem, on_delete=models.CASCADE, related_name='review', null=True, blank=True)
    rating = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        help_text="Rating from 1 to 5 stars"
    )
    title = models.CharField(max_length=200, blank=True)
    comment = models.TextField()
    verified_purchase = models.BooleanField(default=True)
    is_approved = models.BooleanField(default=True)
    helpful_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['product', '-created_at']),
            models.Index(fields=['is_approved']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.product.name} ({self.rating}★)"


class ReviewHelpful(models.Model):
    """Track which users found a review helpful"""
    
    review = models.ForeignKey(Review, on_delete=models.CASCADE, related_name='helpful_votes')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['review', 'user']  # One vote per user per review

    def __str__(self):
        return f"{self.user.username} found review #{self.review.id} helpful"

