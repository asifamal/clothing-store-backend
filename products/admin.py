from django.contrib import admin
from .models import Product, Category, ProductVariant, CategoryAttribute, CategoryAttributeOption, ProductAttribute


class CategoryAttributeInline(admin.TabularInline):
    model = CategoryAttribute
    extra = 1
    fields = ['name', 'attribute_type', 'is_required', 'is_filterable', 'display_order']


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'created_at']
    search_fields = ['name']
    inlines = [CategoryAttributeInline]


class CategoryAttributeOptionInline(admin.TabularInline):
    model = CategoryAttributeOption
    extra = 1
    fields = ['value', 'display_order']


@admin.register(CategoryAttribute)
class CategoryAttributeAdmin(admin.ModelAdmin):
    list_display = ['category', 'name', 'attribute_type', 'is_required', 'is_filterable']
    list_filter = ['category', 'attribute_type', 'is_required', 'is_filterable']
    search_fields = ['name', 'category__name']
    inlines = [CategoryAttributeOptionInline]


@admin.register(CategoryAttributeOption)
class CategoryAttributeOptionAdmin(admin.ModelAdmin):
    list_display = ['attribute', 'value', 'display_order']
    list_filter = ['attribute__category', 'attribute']
    search_fields = ['value', 'attribute__name']


class ProductVariantInline(admin.TabularInline):
    model = ProductVariant
    extra = 1
    fields = ['size', 'stock']


class ProductAttributeInline(admin.TabularInline):
    model = ProductAttribute
    extra = 1
    fields = ['category_attribute', 'value']


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['name', 'price', 'stock', 'category', 'created_at']
    list_filter = ['category', 'created_at']
    search_fields = ['name', 'description']
    readonly_fields = ['created_at', 'updated_at']
    inlines = [ProductVariantInline, ProductAttributeInline]


@admin.register(ProductVariant)
class ProductVariantAdmin(admin.ModelAdmin):
    list_display = ['product', 'size', 'stock', 'created_at']
    list_filter = ['size', 'product']
    search_fields = ['product__name']


@admin.register(ProductAttribute)
class ProductAttributeAdmin(admin.ModelAdmin):
    list_display = ['product', 'category_attribute', 'value']
    list_filter = ['category_attribute__category', 'category_attribute']
    search_fields = ['product__name', 'category_attribute__name', 'value']
