
from .models import *
from rest_framework import fields, serializers
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.utils.timezone import now, timedelta 
from django.contrib.auth import authenticate
User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'role', 'bio', 'photo', 'date_joined']
        read_only_fields = ['id', 'role', 'date_joined']

class ProductImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ['id','image']
        read_only_fields = ['id']

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = '__all__'
        read_only_fields = ['product_id', 'created_at', 'updated_at']
      
        
class SubCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = SubCategory
        fields = ['id', 'name', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']      
        
        
class CategorySerializer(serializers.ModelSerializer):
    
    subcategories= SubCategorySerializer(many=True, read_only=True)
    
    class Meta:
        model = Category
        fields = ['id', 'name', 'created_at', 'updated_at', 'subcategories']
        read_only_fields = ['id', 'created_at', 'updated_at'] 
                   

class SignUpSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True) 
    
    class Meta:
        model = User
        fields = ('email', 'password', 'password2', 'role')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        role = self.context.get('role', 'user')

        validated_data['role'] = role 
        password = validated_data.get('password')
        password2 = validated_data.get('password2')
        if not password:
            raise serializers.ValidationError({"status": "error", "Message": "Password is Required"})
        if not password2:
            raise serializers.ValidationError({"status": "error", "Message": "Confirm Password is Required"})
        if password != password2:
            raise serializers.ValidationError({"status": "error", "Message": "Password and Confirm Password Doesn't Match"})

        if role == 'admin':
            validated_data['is_active'] = True
            validated_data['is_staff'] = True
            validated_data['is_superuser'] = True
        elif role == 'seller':
            validated_data['is_active'] = False
            validated_data['is_staff'] = True
            validated_data['is_superuser'] = False
        else: 
            validated_data['is_active'] = True
            validated_data['is_staff'] = False
            validated_data['is_superuser'] = False

        validated_data.pop('password2') 
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

    
    
class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, data):
        user = authenticate(email=data['email'], password=data['password'])
        if user and user.is_active:
            return user
        raise serializers.ValidationError('User Not Found or Inactive')    


# User can change password using old password
class UserChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)    
    
class PasswordResetRQSerializer(serializers.Serializer):
    email= serializers.EmailField()
    
    def validate_email(self,data):
        try:
            user= User.objects.get(email=data)
        except:
            raise serializers.ValidationError("This Email does not exist!")
        
         
        user.generate_otp()
        send_mail(
             "Password Reset OTP",
            f"Your OTP for password reset is {user.otp}",
            "aboutazizur@gmail.com",
            [user.email],
            fail_silently=False,
        )
        return data
    

class OTPVerifySerializer(serializers.Serializer):
    email= serializers.EmailField()
    otp= serializers.CharField(max_length=6)
    
    def validate(self, attrs):
        try:
            user= User.objects.get(email=attrs["email"])
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "User not found."})
        
        if user.otp!=attrs['otp']:
            raise  serializers.ValidationError({"otp": "Invalid OTP."})
        if user.otp_exp < now(): 
            raise serializers.ValidationError({"otp": "OTP expired."})

        user.otp_verified = True
        user.save()
        

        return attrs
    
class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)    
    
    def validate(self, data):
        try:
             user = User.objects.get(email=data["email"])
             old_password = user.password
        except User.DoesNotExist:
             raise serializers.ValidationError({"email": "User not found."})

        if not user.otp_verified:
             raise serializers.ValidationError({"otp": "OTP verification required."})
         
        if user.otp!=data['otp']:
            raise  serializers.ValidationError({"otp": "Invalid OTP."}) 

        if user.otp_exp < now():
            raise serializers.ValidationError({"otp": "OTP has expired."})
        
        if not data.get("new_password"):
            raise serializers.ValidationError({"new_password": "New password is required."})
        
        if user.check_password(data["new_password"]):
            raise serializers.ValidationError({"new_password": "New password cannot be the same as the old password!"})


        return data
    
    def save(self, **kwargs):
        user = User.objects.get(email=self.validated_data["email"])
        user.set_password(self.validated_data["new_password"])
        user.otp = None  
        user.otp_exp = None
        user.otp_verified = False  
        user.save()
        return user
    
    
class ProductSerializer(serializers.ModelSerializer):
    seller = UserSerializer(read_only=True)

    class Meta:
        model = Product
        fields = ['product_id', 'seller', 'product_name', 'product_desc', 'category',
                  'sub_category', 'price', 'publish_date', 'product_image', 'created_at', 'updated_at']   