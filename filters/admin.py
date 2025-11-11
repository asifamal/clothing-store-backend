from django.contrib import admin
from .models import Filter, FilterOption, ProductFilterValue


@admin.register(Filter)
class FilterAdmin(admin.ModelAdmin):
    list_display = ['name', 'created_at']
    search_fields = ['name']


@admin.register(FilterOption)
class FilterOptionAdmin(admin.ModelAdmin):
    list_display = ['filter', 'value', 'created_at']
    list_filter = ['filter']


@admin.register(ProductFilterValue)
class ProductFilterValueAdmin(admin.ModelAdmin):
    list_display = ['product', 'filter_option', 'created_at']
    list_filter = ['filter_option__filter']
