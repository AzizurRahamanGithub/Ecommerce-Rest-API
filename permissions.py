from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied 

class IsSellerOrAdminUserAndReadOnly(permissions.BasePermission):
    """
    Allow sellers and admins to create/update/delete.
    Others can only read.
    """
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        if not (request.user.is_authenticated and request.user.role in ['seller', 'admin']):
            raise PermissionDenied({"success": False, "massege":"You are not allowed to perform this action. Only sellers and admins can modify.", "status": 403})
        return True

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        if not (obj.seller == request.user or request.user.role == 'admin'):
            raise PermissionDenied({"success": False, "massege":"You are not allowed to perform this action. Only the seller or admin can modify this product.", "status": 403})
        return True



from rest_framework.permissions import SAFE_METHODS

class IsSellerOrAdminUserOrReadOnly(permissions.BasePermission):
    """
    Allow access to users with role 'seller' or 'admin' can modify and role with user only can get.
    # """
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        user= request.user
        if user and user.is_authenticated and user.role in ['admin','seller']:
            return True
        raise PermissionDenied({
            "success": False,
            "message": "Access denied: Only sellers or admins are allowed.",
            "status": 403,
            "Your role": request.user.role
            
        })
    
    def has_object_permission(self, request, view, obj):
        user= request.user
        if user.role == 'admin':
            return True
        if request.method in SAFE_METHODS:
            return True
        if user.role == 'seller' and obj.seller == request.user:
            return True  
        raise PermissionDenied({
            "success": False,
            "message": "Access denied: Only sellers or admins are allowed.",
            "status": 403,
            "Your role": request.user.role
            
        })
        
class IsUserOrAdminUser(permissions.BasePermission):
    """
    Allow access to users with role 'user' or 'admin'.
    """
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated and request.user.role in ['user', 'admin']:
            return True
        raise PermissionDenied({
            "success": False,
            "message": "Access denied: Only sellers or admins are allowed.",
            "status": 403,
            "Your role": request.user.role
            
        })        

class IsAdminOrReadOnlyForOthers(permissions.BasePermission):
    """
    - Allow full access to users with role 'admin'.
    - Allow read-only access to users with role 'seller' or 'user'.
    """

    def has_permission(self, request, view):
        user = request.user
        # Safe methods: GET, HEAD, OPTIONS
        if request.method in permissions.SAFE_METHODS:
            return True

        if user and user.is_authenticated and user.role == 'admin':
            return True

        raise PermissionDenied({
            "success": False,
            "message": "Access denied: Only admins can perform this action.",
            "status": 403,
            "Your role": getattr(user, 'role', 'Anonymous')
        })
