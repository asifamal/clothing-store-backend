from django.contrib import admin
from .models import Review, ReviewHelpful


@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    list_display = ['id', 'product', 'user', 'rating', 'verified_purchase', 'is_approved', 'helpful_count', 'created_at']
    list_filter = ['rating', 'is_approved', 'verified_purchase', 'created_at']
    search_fields = ['product__name', 'user__username', 'comment']
    readonly_fields = ['created_at', 'updated_at', 'helpful_count']
    list_editable = ['is_approved']


@admin.register(ReviewHelpful)
class ReviewHelpfulAdmin(admin.ModelAdmin):
    list_display = ['id', 'review', 'user', 'created_at']
    list_filter = ['created_at']
    search_fields = ['review__id', 'user__username']

