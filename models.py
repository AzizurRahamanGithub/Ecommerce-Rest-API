from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone
import random
from datetime import timedelta
from django.conf import settings


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, role='user', **extra_fields):
        if not email:
            raise ValueError("Email is required!")
        email = self.normalize_email(email)

        extra_fields.setdefault('role', role)

        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'admin')

        return self.create_user(email, password, **extra_fields)



def user_photo_upload_path(instance, filename):
    return f"user_{instance.id}/{filename}"


class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ('user', 'User'),
        ('seller', 'Seller'),
        ('admin', 'Admin'),
    )
    
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    bio = models.TextField(blank=True, null=True)
    photo = models.ImageField(upload_to=user_photo_upload_path, blank=True, null=True)
    
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_exp = models.DateTimeField(blank=True, null=True)
    otp_verified = models.BooleanField(default=False)

    objects = UserManager()
    USERNAME_FIELD = 'email'

    def generate_otp(self):
        self.otp = str(random.randint(100000, 999999))
        self.otp_exp = timezone.now() + timedelta(minutes=10)
        self.otp_verified = False
        self.save()

    def __str__(self):
        return self.email
    
class UserToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE) 
    access_jti = models.CharField(max_length=255, unique=True)
    refresh_token = models.TextField()

class Category(models.Model):
    name = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "MY Category"
        verbose_name_plural = "MY Categories"
    
    def __str__(self):
        return self.name

class SubCategory(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='subcategories')
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('category', 'name')
        verbose_name = "Sub Category"
        verbose_name_plural = "Sub Categories"
    
    def __str__(self):
        return f"{self.category.name} - {self.name}"



class Product(models.Model):
    product_id = models.AutoField(primary_key=True)
    seller = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='products')
    product_name = models.CharField(max_length=255)
    product_desc = models.TextField()
    category = models.ForeignKey(Category, on_delete=models.PROTECT, related_name='products')
    sub_category = models.ForeignKey(SubCategory, on_delete=models.PROTECT, related_name='products')

    price = models.IntegerField()
    publish_date = models.DateField()
    product_image = models.ImageField(upload_to='shop/images')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True) 

    def __str__(self):
        return f"{self.product_id} - {self.product_name}"
    
class ProductImage(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='shop/product_images')

    def __str__(self):
        return f"Image for {self.product.product_name}"
    
    class Meta:
        verbose_name = "Product Image"
        verbose_name_plural = "Product Images"