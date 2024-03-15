from django.urls import path
from .views import RegisterUserView, LoginUserView, ConfirmEmailView, ResendConfirmationEmailView
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

urlpatterns = [
    path('register/', RegisterUserView.as_view(), name='register'),
    path('login/', LoginUserView.as_view(), name='login'),
    path('confirm-email/<str:token>/', ConfirmEmailView.as_view(), name='confirm-email'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('resend-confirmation-email/', ResendConfirmationEmailView.as_view(), name='resend_confirmation_email'),

]