from django.urls import path,include
from .views import SignUpView,LogoutView, UserChangePasswordAPIView,UserProfileDetailAPIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from .views import PasswordResetRQAPIView, OTPVerifyAPIView, PasswordResetAPIView,UserProfileAPIView,AdminUserListAPIView, AdminUserDetailAPIView, ProductListCreateAPIView,ProductDetailAPIView
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
    
    path('auth/signup/', SignUpView.as_view(), name='signup'),
    path('auth/login/', TokenObtainPairView.as_view(), name='login'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),

    path('auth/password-reset/request/', PasswordResetRQAPIView.as_view(), name='password-reset-request'),
    path('auth/password-reset/verify-otp/', OTPVerifyAPIView.as_view(), name='password-reset-verify'),
    path('auth/password-reset/confirm/', PasswordResetAPIView.as_view(), name='password-reset-change'),
    path('auth/change-password/', UserChangePasswordAPIView.as_view(), name="change_password"),

    path('user/profile/', UserProfileAPIView.as_view(), name='user-profile'),
    path('user/<int:id>/', UserProfileDetailAPIView.as_view(), name='user-profile-detail'),
    path("auth/change-password/<int:pk>/", UserChangePasswordAPIView.as_view(), name="change_password"),
    
    path('products/', ProductListCreateAPIView.as_view(), name='product-list-create'),
    path('products/<int:pk>/', ProductDetailAPIView.as_view(), name='product-detail'),
    
    path('admin/users/', AdminUserListAPIView.as_view(), name='admin-user-list'),
    path('admin/users/<int:pk>/', AdminUserDetailAPIView.as_view(), name='admin-user-detail'),

    
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)