from django.urls import path
from .views import RegisterView, VerifyMailView, LogoutView, LoginView, UserView, ResendMailView
from django.contrib.auth import views as auth_views
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path('resend-otp/', ResendMailView.as_view(), name="resend-otp"),
    path('verify/<str:otp>/', VerifyMailView.as_view(), name="verify"),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/', UserView.as_view(), name='profile'),
    path("logout/", LogoutView.as_view(), name='logout'),
    path("refresh/", TokenRefreshView.as_view(), name='refresh token'),
    path('reset_password/', auth_views.PasswordResetView.as_view(),
         name='reset_password'),
    path('reset_password_sent/', auth_views.PasswordResetDoneView.as_view(),
         name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(),
         name='password_reset_confirm'),
    path('reset_password_complete/', auth_views.PasswordResetCompleteView.as_view(),
         name='password_reset_complete'),
]
