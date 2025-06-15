
from django.shortcuts import render

# Create your views here.
from .models import *
from rest_framework.exceptions import ValidationError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, viewsets, permissions
from rest_framework.permissions import IsAuthenticated
from .serializers import SignUpSerializer,ProductSerializer,UserSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model

from .permissions import IsSellerUser, IsSellerOrReadOnly

from .serializers import  UserChangePasswordSerializer, PasswordResetRQSerializer,OTPVerifySerializer,PasswordResetSerializer

User = get_user_model()


class UserProfileAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSellerUser]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response({'success': True, 'data': serializer.data})

    def put(self, request):
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'success': True, 'data': serializer.data})
        return Response({'success': False, 'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        user = request.user
        user.delete()
        return Response({'success': True, 'message': 'User profile deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)


class UserProfileDetailAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSellerUser]

    def get(self, request, id=None):
        if id:
            try:
                user = User.objects.get(id=id)
            except User.DoesNotExist:
                return Response({'success': False, 'message': 'User not found.'}, status=404)
        else:
            user = request.user

        serializer = UserSerializer(user)
        return Response({'success': True, 'data': serializer.data})


class SignUpView(APIView):
    permission_classes = []

    def post(self, request):
        # Forcefully set is_seller=True during seller signup
        request.data['is_seller'] = True  

        password = request.data.get('password')
        confirm_password = request.data.get('password2')

        if password != confirm_password:
            raise ValidationError({'password_mismatch': 'Password fields did not match.'})

        serializer = SignUpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


    
class LogoutView(APIView):
    permission_classes = [IsAuthenticated, IsSellerUser]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Logout successful"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)  


    
class UserChangePasswordAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSellerUser]

    def put(self, request, pk):
        serializer = UserChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            old_password = serializer.validated_data["old_password"]
            new_password = serializer.validated_data["new_password"]

            try:
                user = User.objects.get(pk=pk)
            except User.DoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            if not user.check_password(old_password):
                return Response({"error": "Old password does not match"}, status=status.HTTP_400_BAD_REQUEST)

            user.set_password(new_password)
            user.save()
            return Response({"success": "Password changed successfully"}, status=status.HTTP_200_OK)

        return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)    


class PasswordResetRQAPIView(APIView):
    permission_classes= []
    
    def post(self,request):
        serializer= PasswordResetRQSerializer(data= request.data)
        if serializer.is_valid():
            return Response(
                {"success": True, "message": "OTP sent to email."}, 
                status=status.HTTP_200_OK
            )
        return Response(
            {"success": False, "errors": serializer.errors}, 
            status=status.HTTP_400_BAD_REQUEST
        )    
        
        
class OTPVerifyAPIView(APIView):
    permission_classes= []
    
    def post(self, request):
        serializer= OTPVerifySerializer(data= request.data)
        
        if serializer.is_valid():
            return Response(
                {"success": True, "message": "OTP verified successfully."},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"success": False, "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )     
           
           
class PasswordResetAPIView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"success": True, "message": "Password reset successfully."},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"success": False, "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )           


class ProductListCreateAPIView(APIView):
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def get(self, request):
        products = Product.objects.all()
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()  # optionally, add seller=request.user if you want
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProductDetailAPIView(APIView):
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def get_object(self, pk):
        try:
            return Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return None

    def get(self, request, pk):
        product = self.get_object(pk)
        if product is None:
            return Response({"error": "Product not found."}, status=status.HTTP_404_NOT_FOUND)
        serializer = ProductSerializer(product)
        return Response(serializer.data)

    def put(self, request, pk):
        product = self.get_object(pk)
        if product is None:
            return Response({"error": "Product not found."}, status=status.HTTP_404_NOT_FOUND)
        serializer = ProductSerializer(product, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        product = self.get_object(pk)
        if product is None:
            return Response({"error": "Product not found."}, status=status.HTTP_404_NOT_FOUND)
        serializer = ProductSerializer(product, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        product = self.get_object(pk)
        if product is None:
            return Response({"error": "Product not found."}, status=status.HTTP_404_NOT_FOUND)
        product.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    

class AdminUserListAPIView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response({'success': True, 'data': serializer.data}, status=status.HTTP_200_OK)


class AdminUserDetailAPIView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response({'success': False, 'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserSerializer(user)
        return Response({'success': True, 'data': serializer.data}, status=status.HTTP_200_OK)