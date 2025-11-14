from django.db import models
from django.core.validators import MinValueValidator


class Category(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name_plural = 'Categories'
        ordering = ['name']
    
    def __str__(self):
        return self.name


class Product(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, validators=[MinValueValidator(0)])
    stock = models.IntegerField(validators=[MinValueValidator(0)], default=0)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='products')
    image = models.ImageField(upload_to='products/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return self.name
    
    @property
    def discounted_price(self):
        """For now, return the regular price. Can be extended for discount logic later."""
        return self.price


class ProductVariant(models.Model):
    SIZE_CHOICES = [
        ('XS', 'Extra Small'),
        ('S', 'Small'),
        ('M', 'Medium'),
        ('L', 'Large'),
        ('XL', 'Extra Large'),
        ('XXL', '2X Large'),
    ]
    
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='variants')
    size = models.CharField(max_length=10, choices=SIZE_CHOICES)
    stock = models.IntegerField(validators=[MinValueValidator(0)], default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['product', 'size']
        ordering = ['size']
    
    def __str__(self):
        return f"{self.product.name} - {self.size}"


class CategoryAttribute(models.Model):
    """Define category-specific attributes like sleeve length, fit type, etc."""
    ATTRIBUTE_TYPES = [
        ('text', 'Text'),
        ('number', 'Number'),
        ('select', 'Dropdown Selection'),
        ('multiselect', 'Multiple Selection'),
    ]
    
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='attributes')
    name = models.CharField(max_length=100)  # e.g., "Sleeve Length", "Fit Type"
    attribute_type = models.CharField(max_length=20, choices=ATTRIBUTE_TYPES)
    is_required = models.BooleanField(default=False)
    is_filterable = models.BooleanField(default=True)  # Can be used as filter on frontend
    display_order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['category', 'name']
        ordering = ['display_order', 'name']
    
    def __str__(self):
        return f"{self.category.name} - {self.name}"


class CategoryAttributeOption(models.Model):
    """Predefined options for select/multiselect attributes"""
    attribute = models.ForeignKey(CategoryAttribute, on_delete=models.CASCADE, related_name='options')
    value = models.CharField(max_length=100)  # e.g., "Long Sleeve", "Short Sleeve"
    display_order = models.PositiveIntegerField(default=0)
    
    class Meta:
        unique_together = ['attribute', 'value']
        ordering = ['display_order', 'value']
    
    def __str__(self):
        return f"{self.attribute.name}: {self.value}"


class ProductAttribute(models.Model):
    """Store actual attribute values for products"""
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='attributes')
    category_attribute = models.ForeignKey(CategoryAttribute, on_delete=models.CASCADE)
    value = models.TextField()  # Store value as text (can be JSON for multiselect)
    
    class Meta:
        unique_together = ['product', 'category_attribute']
    
    def __str__(self):
        return f"{self.product.name} - {self.category_attribute.name}: {self.value}"
