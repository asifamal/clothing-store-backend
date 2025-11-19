from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db.models import Avg, Count, Q
from .models import Review, ReviewHelpful
from .serializers import (
    ReviewSerializer, ReviewCreateSerializer, ReviewUpdateSerializer,
    AdminReviewSerializer
)


class IsOwnerOrReadOnly(permissions.BasePermission):
    """Allow read for all, write only for owner"""
    
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.user == request.user


class ReviewViewSet(viewsets.ModelViewSet):
    """ViewSet for product reviews"""
    
    queryset = Review.objects.filter(is_approved=True).select_related('user', 'product')
    serializer_class = ReviewSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly, IsOwnerOrReadOnly]

    def get_serializer_class(self):
        if self.action == 'create':
            return ReviewCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return ReviewUpdateSerializer
        return ReviewSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        product_id = self.request.query_params.get('product')
        
        if product_id:
            queryset = queryset.filter(product_id=product_id)
        
        # Filter by rating
        rating = self.request.query_params.get('rating')
        if rating:
            queryset = queryset.filter(rating=rating)
        
        # Filter verified purchases only
        verified_only = self.request.query_params.get('verified_only')
        if verified_only == 'true':
            queryset = queryset.filter(verified_purchase=True)
        
        return queryset

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Check if order item already has a review
        order_item_id = request.data.get('order_item')
        if order_item_id and Review.objects.filter(order_item_id=order_item_id).exists():
            return Response(
                {"detail": "You have already reviewed this item"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        self.perform_create(serializer)
        
        # Use ReviewSerializer for the response
        review = Review.objects.get(id=serializer.instance.id)
        response_serializer = ReviewSerializer(review, context={'request': request})
        headers = self.get_success_headers(response_serializer.data)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        # Get order_item from request data
        order_item_id = self.request.data.get('order_item')
        
        # Get the OrderItem instance if provided
        order_item = None
        if order_item_id:
            from orders.models import OrderItem
            try:
                order_item = OrderItem.objects.get(id=order_item_id)
            except OrderItem.DoesNotExist:
                pass
        
        # All reviews are auto-approved and verified
        serializer.save(
            user=self.request.user, 
            verified_purchase=True,
            is_approved=True,
            order_item=order_item
        )

    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAuthenticated])
    def mark_helpful(self, request, pk=None):
        """Mark a review as helpful"""
        review = self.get_object()
        
        # Check if user already voted
        helpful_vote, created = ReviewHelpful.objects.get_or_create(
            review=review,
            user=request.user
        )
        
        if created:
            review.helpful_count += 1
            review.save()
            return Response({"detail": "Marked as helpful", "helpful_count": review.helpful_count})
        else:
            # Remove vote
            helpful_vote.delete()
            review.helpful_count = max(0, review.helpful_count - 1)
            review.save()
            return Response({"detail": "Vote removed", "helpful_count": review.helpful_count})

    @action(detail=False, methods=['get'])
    def my_reviews(self, request):
        """Get current user's reviews"""
        if not request.user.is_authenticated:
            return Response({"detail": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)
        
        reviews = Review.objects.filter(user=request.user).select_related('product')
        serializer = self.get_serializer(reviews, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def product_stats(self, request):
        """Get review statistics for a product"""
        product_id = request.query_params.get('product')
        if not product_id:
            return Response({"detail": "Product ID required"}, status=status.HTTP_400_BAD_REQUEST)
        
        reviews = Review.objects.filter(product_id=product_id, is_approved=True)
        
        stats = {
            'total_reviews': reviews.count(),
            'average_rating': reviews.aggregate(Avg('rating'))['rating__avg'] or 0,
            'rating_distribution': {
                '5': reviews.filter(rating=5).count(),
                '4': reviews.filter(rating=4).count(),
                '3': reviews.filter(rating=3).count(),
                '2': reviews.filter(rating=2).count(),
                '1': reviews.filter(rating=1).count(),
            },
            'verified_purchases': reviews.filter(verified_purchase=True).count(),
        }
        
        return Response(stats)


class AdminReviewViewSet(viewsets.ModelViewSet):
    """Admin viewset for managing all reviews"""
    
    queryset = Review.objects.all().select_related('user', 'product').order_by('-created_at')
    serializer_class = AdminReviewSerializer
    permission_classes = [permissions.IsAdminUser]

    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filter by approval status
        is_approved = self.request.query_params.get('is_approved')
        if is_approved is not None:
            queryset = queryset.filter(is_approved=is_approved.lower() == 'true')
        
        # Filter by rating
        rating = self.request.query_params.get('rating')
        if rating:
            queryset = queryset.filter(rating=rating)
        
        # Search by username or product name
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(user__username__icontains=search) |
                Q(product__name__icontains=search) |
                Q(comment__icontains=search)
            )
        
        return queryset

    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve a review"""
        review = self.get_object()
        review.is_approved = True
        review.save()
        return Response({"detail": "Review approved"})

    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject/hide a review"""
        review = self.get_object()
        review.is_approved = False
        review.save()
        return Response({"detail": "Review rejected"})

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get overall review statistics"""
        total_reviews = Review.objects.count()
        approved_reviews = Review.objects.filter(is_approved=True).count()
        pending_reviews = Review.objects.filter(is_approved=False).count()
        
        avg_rating = Review.objects.filter(is_approved=True).aggregate(
            Avg('rating')
        )['rating__avg'] or 0
        
        return Response({
            'total_reviews': total_reviews,
            'approved_reviews': approved_reviews,
            'pending_reviews': pending_reviews,
            'average_rating': round(avg_rating, 2),
        })

