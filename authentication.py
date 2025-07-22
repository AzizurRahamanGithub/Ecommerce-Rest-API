from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken

class CustomJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        result = super().authenticate(request)
        if result is None:
            return None

        user, validated_token = result

        # Blacklist check
        if hasattr(validated_token, 'jti'):
            if BlacklistedToken.objects.filter(token__jti=validated_token['jti']).exists():
                raise InvalidToken('Token is blacklisted')

        return (user, validated_token)
