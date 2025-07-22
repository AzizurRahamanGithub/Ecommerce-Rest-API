from django.urls import path,include
from .views import LogoutView,UserProfileDetailAPIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from .views import PasswordResetRQAPIView, OTPVerifyAPIView, PasswordResetAPIView,UserProfileAPIView, ProductListCreateAPIView,ProductDetailAPIView
from .views import UserSignUpView, SellerSignUpView, AdminSignUpView, AdminUserManagementView, CategoryDetailAPIView
from .views import UserChangeOwnPasswordView, AdminChangeUserPasswordView, UserLoginView, CategoryListCreateAPIView
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    # path('signup/', SignUpView.as_view(), name='signup'),
    # path('login/', TokenObtainPairView.as_view(), name='login'),
    # path('logout/', LogoutView.as_view(), name='logout'),
    # path('pass-reset/request/', PasswordResetRQAPIView.as_view(), name='password-reset-request'),
    # path('pass-reset/otp-verify/', OTPVerifyAPIView.as_view(), name='password-reset-verify'),
    # path('pass-reset/change-pass/', PasswordResetAPIView.as_view(), name='password-reset-change'),
    # path('profile/', UserProfileAPIView.as_view(), name='user-profile'),
    # path('user-profile/<int:id>/', UserProfileDetailAPIView.as_view()),
    # path("change-password/<int:pk>/", UserChangePasswordAPIView.as_view(), name="change_password"),
    path('api-auth/', include('rest_framework.urls')),
    
    # path('auth/signup/', SignUpView.as_view(), name='signup'),

    path('signup/user/', UserSignUpView.as_view(), name='user-signup'),
    path('signup/seller/', SellerSignUpView.as_view(), name='seller-signup'),
    path('signup/admin/', AdminSignUpView.as_view(), name='admin-signup'),
    
    # path('auth/login/', TokenObtainPairView.as_view(), name='login'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('login/', UserLoginView.as_view(), name='user-login'),

    path('auth/password-reset/request/', PasswordResetRQAPIView.as_view(), name='password-reset-request'),
    path('auth/password-reset/verify-otp/', OTPVerifyAPIView.as_view(), name='password-reset-verify'),
    path('auth/password-reset/confirm/', PasswordResetAPIView.as_view(), name='password-reset-change'),
    path("auth/change-password/", UserChangeOwnPasswordView.as_view(), name="user-change-password"),
    path("auth/admin/change-password/<int:pk>/", AdminChangeUserPasswordView.as_view(), name="admin-change-password"),

    # path("auth/change-password/user/<int:pk>/", AdminChangeUserPasswordView.as_view(), name="admin-change-password"),
    path('user/profile/', UserProfileAPIView.as_view(), name='user-profile'),
    path('user/<int:id>/', UserProfileDetailAPIView.as_view(), name='user-profile-detail'),
    
    path('products/', ProductListCreateAPIView.as_view(), name='product-list-create'),
    path('products/<int:pk>/', ProductDetailAPIView.as_view(), name='product-detail'),
    
    path('categories/', CategoryListCreateAPIView.as_view(), name='category-list-create'),
    path('categories/<int:pk>/', CategoryDetailAPIView.as_view(), name='category-detail'),
    
    path('admin/users/', AdminUserManagementView.as_view(), name='admin-users'),
    path('admin/users/<int:user_id>/', AdminUserManagementView.as_view(), name='admin-user-delete'),

    
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)