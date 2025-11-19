from rest_framework import serializers
from .models import Review, ReviewHelpful
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()


class ReviewUserSerializer(serializers.ModelSerializer):
    """Serializer for user info in reviews"""
    
    class Meta:
        model = User
        fields = ['id', 'username']


class ReviewSerializer(serializers.ModelSerializer):
    """Serializer for product reviews"""
    
    user = ReviewUserSerializer(read_only=True)
    user_has_voted = serializers.SerializerMethodField()
    
    class Meta:
        model = Review
        fields = [
            'id', 'product', 'user', 'rating', 'title', 'comment',
            'verified_purchase', 'is_approved', 'helpful_count',
            'user_has_voted', 'created_at', 'updated_at'
        ]
        read_only_fields = ['user', 'verified_purchase', 'helpful_count', 'is_approved']

    def get_user_has_voted(self, obj):
        """Check if current user has voted this review as helpful"""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return ReviewHelpful.objects.filter(review=obj, user=request.user).exists()
        return False

    def validate_rating(self, value):
        """Validate rating is between 1 and 5"""
        if value < 1 or value > 5:
            raise serializers.ValidationError("Rating must be between 1 and 5")
        return value

    def create(self, validated_data):
        """Create review with current user"""
        request = self.context.get('request')
        validated_data['user'] = request.user
        
        # Check if user has purchased this product
        from orders.models import OrderItem
        product = validated_data['product']
        has_purchased = OrderItem.objects.filter(
            order__user=request.user,
            product=product,
            order__status__in=['Processing', 'Shipped', 'Delivered']
        ).exists()
        validated_data['verified_purchase'] = has_purchased
        
        return super().create(validated_data)


class ReviewCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating reviews"""
    
    order_item = serializers.IntegerField(required=False, allow_null=True, write_only=True)
    
    class Meta:
        model = Review
        fields = ['product', 'rating', 'title', 'comment', 'order_item']
        read_only_fields = []

    def validate(self, data):
        """Check if user already reviewed this order item"""
        request = self.context.get('request')
        order_item_id = data.get('order_item')
        
        if order_item_id:
            # Check if this order item already has a review
            if Review.objects.filter(order_item_id=order_item_id).exists():
                raise serializers.ValidationError("You have already reviewed this item")
        
        return data


class ReviewUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating reviews"""
    
    class Meta:
        model = Review
        fields = ['rating', 'title', 'comment']


class AdminReviewSerializer(serializers.ModelSerializer):
    """Serializer for admin review management"""
    
    user = ReviewUserSerializer(read_only=True)
    product_name = serializers.CharField(source='product.name', read_only=True)
    product_image = serializers.CharField(source='product.image', read_only=True)
    
    class Meta:
        model = Review
        fields = [
            'id', 'product', 'product_name', 'product_image', 'user',
            'rating', 'title', 'comment', 'verified_purchase',
            'is_approved', 'helpful_count', 'created_at', 'updated_at'
        ]
        read_only_fields = ['user', 'product', 'verified_purchase', 'helpful_count']
