from django.db import models


class Filter(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name


class FilterOption(models.Model):
    filter = models.ForeignKey(Filter, on_delete=models.CASCADE, related_name='options')
    value = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['filter', 'value']
    
    def __str__(self):
        return f"{self.filter.name}: {self.value}"


class ProductFilterValue(models.Model):
    product = models.ForeignKey('products.Product', on_delete=models.CASCADE, related_name='filter_values')
    filter_option = models.ForeignKey(FilterOption, on_delete=models.CASCADE, related_name='product_values')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['product', 'filter_option']
    
    def __str__(self):
        return f"{self.product.name} - {self.filter_option}"
