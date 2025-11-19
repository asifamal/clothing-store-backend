from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ReviewViewSet, AdminReviewViewSet

router = DefaultRouter()
router.register('reviews', ReviewViewSet, basename='review')
router.register('admin/reviews', AdminReviewViewSet, basename='admin-review')

urlpatterns = router.urls
