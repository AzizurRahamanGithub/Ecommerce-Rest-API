from rest_framework import permissions

class IsSellerOrReadOnly(permissions.BasePermission):
    """
    Sellers can create/update/delete.
    Normal users can only read.
    """
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:  # GET, HEAD, OPTIONS
            return True
        return request.user.is_authenticated and request.user.role == 'seller'

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.seller == request.user


class IsSellerUser(permissions.BasePermission):
    """
    Permission to only allow seller users.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role == 'seller')
