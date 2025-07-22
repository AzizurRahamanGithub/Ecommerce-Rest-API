
from django.conf import settings
from django.shortcuts import render
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model

# Create your views here.
import jwt
from .models import *
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status, viewsets, permissions
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from .serializers import SignUpSerializer,ProductSerializer,UserSerializer, UserLoginSerializer, CategorySerializer
from .serializers import  UserChangePasswordSerializer, PasswordResetRQSerializer,OTPVerifySerializer,PasswordResetSerializer

User = get_user_model()


class BaseAPIView(APIView):
    
    def success_response(self, message="Thank you for your request", data=None, status_code= status.HTTP_200_OK):
        return Response(
            {
            "success": True,
            "message": message,
            "status_code": status_code,
            "data": data or {}
            }, 
            status=status_code )
        
    def error_response(self, message="I am sorry for your request", data=None, status_code= status.HTTP_400_BAD_REQUEST):
        return Response(
            {
            "success": False,
            "message": message,
            "status_code": status_code,
            "data": data or {}
            }, 
            status=status_code )    


class AdminUserManagementView(BaseAPIView ):
   
   
    def post(self, request):

        serializer = UserSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return self.success_response(message="User created successfully", data=serializer.data, status_code=status.HTTP_201_CREATED)
        except ValidationError as e:
            return self.error_response(message="User creation failed", data=e.detail, status_code=status.HTTP_400_BAD_REQUEST)   
        except Exception as e:
            return self.error_response(message=f"An error occurred: {str(e)}", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
       
            
    
    def get(self, request, pk=None):
        if pk:
            try:
                user= User.objects.get(pk=pk)
            except User.DoesNotExist:
                return self.error_response(message="User not found", status_code=status.HTTP_404_NOT_FOUND)
            
            serializer = UserSerializer(user)
            return self.success_response(message="User retrieved successfully", data=serializer.data)

        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return self.success_response(message="All users retrieved successfully", data=serializer.data)

    def put(self, request, pk=None):
        
        try:
            user= User.objects.get(pk=pk)
        except User.DoesNotExist:
            return self.error_response(message="User not found", status_code=status.HTTP_404_NOT_FOUND)
        
        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return self.success_response(message="User updated successfully", data=serializer.data)
        return self.error_response(message="User update failed", data=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk=None):
        
        try:
            user= User.objects.get(pk=pk)
        except User.DoesNotExist:
            return self.error_response(message="User not found", status_code=status.HTTP_404_NOT_FOUND)
        
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return self.success_response(message="User partially updated successfully", data=serializer.data)
        return self.error_response(message="User partial update failed", data=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk=None):
        
        try:
            user = User.objects.get(pk=pk)
            user.delete()
            return self.success_response(message="User deleted successfully",data={}, status_code=status.HTTP_204_NO_CONTENT)
        except User.DoesNotExist:
            return self.error_response(message="User not found", status_code=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return self.error_response(message=f"An error occurred: {str(e)}", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserProfileAPIView(BaseAPIView):
    permission_classes = [IsAuthenticated]
   
    def get(self, request):
        try:
            serializer= UserSerializer(request.user)
            return self.success_response(message="User profile retrieved successfully", data=serializer.data)
        except Exception as e:
            return self.error_response(message=f"An error occurred: {str(e)}", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request):
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            try:
                serializer.save()
                return self.success_response(message="User profile updated successfully", data=serializer.data)
            except Exception as e:
                return self.error_response(message=f"An error occurred: {str(e)}", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        return self.error_response(message="User profile update failed", data=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        try:
            request.user.delete()
            return self.success_response(message="User profile deleted successfully", status_code=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return self.error_response(message=f"An error occurred: {str(e)}", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
         
class UserProfileDetailAPIView(BaseAPIView):
   
    permission_classes = [IsAuthenticated]

    def get(self, request, id=None):
        try:
            if id:
                user = User.objects.get(id=id)
            else:
                user = request.user

            serializer = UserSerializer(user)
            return self.success_response(
                message="User retrieved successfully.",
                data=serializer.data,
                status_code=status.HTTP_200_OK
            )
        except User.DoesNotExist:
            return self.error_response(
                message="User not found.",
                status_code=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return self.error_response(
                message=f"An unexpected error occurred: {str(e)}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
    def put(self, request, id):
        try:
            user = User.objects.get(id=id)
            serializer = UserSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return self.success_response(message="User updated successfully", data=serializer.data)
            return self.error_response(message="Validation failed", data=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return self.error_response(message="User not found", status_code=status.HTTP_404_NOT_FOUND)

    def delete(self, request, id):
        try:
            user = User.objects.get(id=id)
            user.delete()
            return self.success_response(message="User deleted", status_code=status.HTTP_204_NO_CONTENT)
        except User.DoesNotExist:
            return self.error_response(message="User not found", status_code=status.HTTP_404_NOT_FOUND)
 


class BaseSignUpView(BaseAPIView):
   
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer= SignUpSerializer(data=request.data, context={'role': self.role})
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return self.success_response(
                message=f"{self.role} created successfully",
                data=serializer.data,
                status_code=status.HTTP_201_CREATED
            )
        except ValidationError as e:
            return self.error_response(
                message=f"{self.role} creation failed",
                data=e.detail,
                status_code=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return self.error_response(
                message=f"An error occurred: {str(e)}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )    


class UserSignUpView(BaseSignUpView):
    role = 'user'

class SellerSignUpView(BaseSignUpView):
    role = 'seller'

class AdminSignUpView(BaseSignUpView):
    role = 'admin'


class UserLoginView(BaseAPIView):
   
    permission_classes = [AllowAny]

    def post(self, request):
      serializer = UserLoginSerializer(data=request.data)
      try:
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        access_payload = jwt.decode(
            access_token,
            settings.SECRET_KEY,
            algorithms=["HS256"]
        )
        access_jti = access_payload.get("jti")

        UserToken.objects.update_or_create(
            user=user,
            defaults={
                'access_jti': access_jti,
                'refresh_token': str(refresh)
            }
        )

        return self.success_response(
            message="Login successful",
            data={
                "refresh_token": str(refresh),
                "access_token": access_token,
                "user": serializer.data
            },
            status_code=status.HTTP_200_OK
        )
      except ValidationError as e:
        return self.error_response(
            message="Login failed due to validation error",
            data=e.detail,
            status_code=status.HTTP_400_BAD_REQUEST
        )
      except Exception as e:
        return self.error_response(
            message=f"An unexpected error occurred: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


class LogoutView(BaseAPIView):
   
   

    def post(self, request):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return Response({"error": "Invalid or missing Authorization header."}, status=400)
        
        access_token = auth_header.split(' ')[1]

        try:
            access_payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
            jti = access_payload['jti']

            user_token = UserToken.objects.get(access_jti=jti)
            
            refresh_token_obj = RefreshToken(user_token.refresh_token)
            refresh_token_obj.blacklist()
            
            user_token.delete()

            return self.success_response(
                message="Logout successful",
                data={},
                status_code=status.HTTP_200_OK
            )
        except TokenError:
            return self.error_response(
                message="Token has already been blacklisted or is invalid.",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        except UserToken.DoesNotExist:
            return self.error_response(
                message="UserToken not found for this token.",
                status_code=status.HTTP_404_NOT_FOUND
            )      
        except jwt.ExpiredSignatureError:
            return self.error_response(
                message="Access token expired.",
                status_code=status.HTTP_401_UNAUTHORIZED
            )
        except jwt.DecodeError:
            return self.error_response(
                message="Error decoding token.",
                status_code=status.HTTP_401_UNAUTHORIZED
            )
        except Exception as e:
            return self.error_response(
                message=f"An unexpected error occurred: {str(e)}",
                status_code=status.HTTP_400_BAD_REQUEST
            )             


class ProductDetailAPIView(BaseAPIView):

    def get_object(self, pk):
        try:
            return Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return None

    def get(self, request, pk):
        Product= self.get_object(pk)
        try:
            if Product is None:
                return self.error_response(message="Product not found.", status_code=status.HTTP_404_NOT_FOUND)
            
            self.check_object_permissions(request, Product)
            serializer= ProductSerializer(Product)
            return self.success_response(message="Product retrieved successfully", data=serializer.data)
        
        except Exception as e:
            return self.error_response(message=f"An error occurred: {str(e)}", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self, request, pk):
        product = self.get_object(pk)
        if product is None:
            return self.error_response(message="Product not found.", status_code=status.HTTP_404_NOT_FOUND)
        
        self.check_object_permissions(request, product)
        
        serializer = ProductSerializer(product, data=request.data)
        if serializer.is_valid():
            try:
                serializer.save()
                return self.success_response(message="Product updated successfully", data=serializer.data)
            except Exception as e:
                return self.error_response(message=f"An error occurred: {str(e)}", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return self.error_response(message="Validation failed", data=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        
    
    def patch(self, request, pk):
        Product= self.get_object(pk)
        if Product is None:
            return self.error_response(message="Product not found.", status_code=status.HTTP_404_NOT_FOUND)
        
        self.check_object_permissions(request, Product)
        serializer= ProductSerializer(Product, data=request.data, partial=True)
        if serializer.is_valid():
            try:
                serializer.save()
                return self.success_response(message="Product partially updated successfully", data=serializer.data)
            except Exception as e:
                return self.error_response(message=f"An error occurred: {str(e)}", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return self.error_response(message="Validation failed", data=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)    
       
        
    def delete(self, request, pk):
      try:
        product = self.get_object(pk)
        if product is None:
            return self.error_response(
                message="Product not found.",
                status_code=status.HTTP_404_NOT_FOUND
            )

        self.check_object_permissions(request, product)

        product.delete()
        return self.success_response(
            message="Product deleted successfully.",
            status_code=status.HTTP_204_NO_CONTENT
        )

      except Exception as e:
        return self.error_response(
            message=f"An unexpected error occurred: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
   

class ProductListCreateAPIView(BaseAPIView):    
      
    parser_classes = [MultiPartParser, FormParser] 
    
    
    def post(self, request):
       serializer = ProductSerializer(data=request.data)
       
       try:
        serializer.is_valid(raise_exception=True)
        serializer.save(seller=request.user)
        return self.success_response(
            message="Product created successfully",
            data=serializer.data,
            status_code=status.HTTP_201_CREATED
        )
       except ValidationError as e:
        return self.error_response(
            message="Product creation failed due to validation error",
            data=e.detail,
            status_code=status.HTTP_400_BAD_REQUEST
        )
       except Exception as e:
        return self.error_response(
            message=f"An unexpected error occurred: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


    def get(self, request):
      try:
        product = Product.objects.all()
        
        if not product.exists():
            return self.success_response(
                message="No products found.",
                data=[],
                status_code=status.HTTP_200_OK
            )
        
        serializer = ProductSerializer(product, many=True)
        return self.success_response(
            message="Products retrieved successfully.",
            data=serializer.data,
            status_code=status.HTTP_200_OK
        )
        
      except Exception as e:
        return self.error_response(
            message=f"An unexpected error occurred: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )        

   
class CategoryListCreateAPIView(BaseAPIView):
    
    def get(self, request):
        try:
            categories = Category.objects.all()
            if not categories.exists():
                return self.success_response(
                    message="No categories found.",
                    data=[],
                    status_code=status.HTTP_200_OK
                )
            
            serializer = CategorySerializer(categories, many=True)
            return self.success_response(
                message="Categories retrieved successfully.",
                data=serializer.data,
                status_code=status.HTTP_200_OK
            )
        except Exception as e:
            return self.error_response(
                message=f"An unexpected error occurred: {str(e)}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )   
            
class CategoryDetailAPIView(BaseAPIView):
    def get_object(self, pk):
        try:
            return Category.objects.get(pk=pk)
        except Category.DoesNotExist:
            return None

    def get(self, request, pk):
        category = self.get_object(pk)
        if category is None:
            return self.error_response(message="Category not found.", status_code=status.HTTP_404_NOT_FOUND)
        
        serializer = CategorySerializer(category)
        return self.success_response(message="Category retrieved successfully", data=serializer.data)

   
class UserChangeOwnPasswordView(BaseAPIView):
   
  

    def post(self, request):
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        if not old_password or not new_password:
            return self.error_response(
                message="Both old and new passwords are required.",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        if not user.check_password(old_password):
            return self.error_response(
                message="Old password is incorrect.",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        try:
            user.set_password(new_password)
            user.save()
            return self.success_response(
                message="Password changed successfully.",
                status_code=status.HTTP_200_OK
            )
        except Exception as e:
            return self.error_response(
                message=f"An unexpected error occurred: {str(e)}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminChangeUserPasswordView(BaseAPIView):
   
   

    def post(self, request, pk):
        new_password = request.data.get("new_password")

        if not new_password:
            return self.error_response(
                message="New password is required.",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(pk=pk)
            user.set_password(new_password)
            user.save()

            return self.success_response(
                message=f"Password updated for {user.email}",
                status_code=status.HTTP_200_OK
            )
        except User.DoesNotExist:
            return self.error_response(
                message="User not found.",
                status_code=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return self.error_response(
                message=f"An unexpected error occurred: {str(e)}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PasswordResetRQAPIView(BaseAPIView):
   
   

    def post(self, request):
        serializer = PasswordResetRQSerializer(data=request.data)
        if serializer.is_valid():
            return self.success_response(
                message="OTP sent to email.",
                status_code=status.HTTP_200_OK
            )
        return self.error_response(
            message="OTP sending failed due to validation error.",
            data=serializer.errors,
            status_code=status.HTTP_400_BAD_REQUEST
        )

        
class OTPVerifyAPIView(BaseAPIView):
   
  
    
    def post(self, request):
        serializer= OTPVerifySerializer(data= request.data)
        if serializer.is_valid():
            return self.success_response(
                message="OTP verified successfully.",
                status_code=status.HTTP_200_OK
            )
        return self.error_response(
            message="OTP sending failed due to validation error.",
            data=serializer.errors,
            status_code=status.HTTP_400_BAD_REQUEST
        )
           
           
class PasswordResetAPIView(BaseAPIView):
   
    

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return self.success_response(
                message="Password reset successfully.", data=serializer.data, status_code=status.HTTP_200_OK )
            
        return self.error_response( message="Password reset failed due to validation error.",
            data=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST )       

