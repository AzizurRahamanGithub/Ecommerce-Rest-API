from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from django.http import HttpRequest
from .models import User, Category, SubCategory, Product

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ('id', 'email', 'first_name', 'last_name', 'role', 'is_active', 'is_staff', "is_superuser", 'date_joined', 'last_login')
    list_display_links = ('id', 'email')
    list_filter = ('role', 'is_active', 'is_staff', 'is_superuser')
    search_fields = ('id', 'email', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    filter_horizontal = ('groups', 'user_permissions',)

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal Info'), {'fields': ('first_name', 'last_name', 'bio', 'photo')}),
        (_('Permissions'), {
            'fields': ('role', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
        (_('OTP Info'), {'fields': ('otp', 'otp_exp', 'otp_verified')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'role', 'is_staff', 'is_superuser'),
        }),
    )

    def get_readonly_fields(self, request, obj=None):
        if obj and obj.is_superuser:
            return self.readonly_fields + ('role',)
        return self.readonly_fields


    actions = ['activate_users', 'deactivate_users']
    
    def has_delete_permission(self, request: HttpRequest, obj=None) -> bool:
        return request.user.is_superuser
    
    def has_change_permission(self, request: HttpRequest, obj=None) -> bool:
        return request.user.is_superuser or (obj and request.user == obj)
    
    def activate_users(self, request, queryset):
        queryset.update(is_active=True)
    activate_users.short_description = _("Activate selected users")
    
    def deactivate_users(self, request, queryset):
        queryset.update(is_active=False)
    deactivate_users.short_description = _("Deactivate selected users")

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'product_count', 'created_at')
    search_fields = ('id', 'name')
    readonly_fields = ('created_at', 'updated_at')
    
    def product_count(self, obj):
        return obj.products.count()
    product_count.short_description = _('Products')
    
    def has_delete_permission(self, request: HttpRequest, obj=None) -> bool:
        return request.user.is_superuser

@admin.register(SubCategory)
class SubCategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'category', 'product_count', 'created_at')
    list_filter = ('category',)
    search_fields = ('id', 'name', 'category__name')
    readonly_fields = ('created_at', 'updated_at')
    
    def product_count(self, obj):
        return obj.products.count()
    product_count.short_description = _('Products')
    
    def has_delete_permission(self, request: HttpRequest, obj=None) -> bool:
        return request.user.is_superuser

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('product_id', 'product_name', 'seller', 'category', 'sub_category', 'price', 'publish_date')
    list_filter = ('category', 'sub_category', 'publish_date')
    search_fields = ('product_id', 'product_name', 'seller__email', 'product_desc')
    raw_id_fields = ('seller',)
    readonly_fields = ('created_at', 'updated_at')
    date_hierarchy = 'publish_date'

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        return qs.filter(seller=request.user)

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        if not request.user.is_superuser:
            if 'seller' in form.base_fields:
                form.base_fields['seller'].disabled = True
        return form

    def has_change_permission(self, request, obj=None) -> bool:
        if obj is None: 
            return True
        return request.user.is_superuser or obj.seller == request.user

    def has_delete_permission(self, request: HttpRequest, obj=None) -> bool:
        if obj is None:
            return True
        return request.user.is_superuser or obj.seller == request.user



admin.site.register(User, CustomUserAdmin)