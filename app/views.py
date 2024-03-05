from django.shortcuts import render
from rest_framework.decorators import APIView
from rest_framework.response import Response
from .models import User
from .serializer import RegisterUserSerializer, UserProfileSerializer
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from django.middleware import csrf
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import decorators, permissions as rest_permissions
from rest_framework_simplejwt import tokens
from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist


def get_user_token(user):
    refresh = RefreshToken.for_user(user)
    return (
        {
            'refresh_token': str(refresh),
            'access_token': str(refresh.access_token)
        }
    )


class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save(validated_data=request.data)
            user.generate_otp()
            self.send_verification_mail(request, user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def send_verification_mail(self, request, user):
        otp = user.generate_otp()
        subject = "verification mail"
        verification_url = reverse('verify', args=[otp])
        otp_part = verification_url.split('/')[-2]
        message = f'Hi {user.email},\n' \
            f'Thank you for registering in the Django React project created by Rohit Joshi for GitHub:\n' \
            f'This is your verification OTP:\n' \
            f'{otp_part}\n' \
            f'Thank You\n' \
            f'With Regards from Team Rohit Joshi Task Manager'

        return send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])


class ResendMailView(APIView):
    def post(self, request):
        emails = request.data.get("email")

        if not emails:
            raise AuthenticationFailed("No emails provided")

        if isinstance(emails, str):
            emails = emails.split(',')

        success_messages = []
        error_messages = []

        for email in emails:
            try:
                user = User.objects.get(email=email, is_active=False)
            except ObjectDoesNotExist:
                error_messages.append(
                    f"User with email {email} not found or already verified")
                continue
        otp = user.generate_otp()

        if self.otp_mail(request, user):
            success_messages.append(f"OTP resent to {emails}")
        else:
            error_messages.append(f"Failed to send OTP email to {emails}")

        response_data = {
            "success_messages": success_messages,
            "error_messages": error_messages
        }

        return Response(response_data)

    def otp_mail(self, request, user):
        otp = user.verification_otp

        subject = "Verification OTP Resent"

        verification_url = reverse('verify', args=[otp])
        otp_part = verification_url.split('/')[-2]

        message = f'Hi {user.email},\n' \
            f'Your verification OTP has been resent:\n' \
            f'{otp_part}\n' \
            f'Thank You\n' \
            f'With Regards from Team Rohit Joshi Task Manager'

        try:
            send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])
            return True
        except Exception as e:
            return False


class VerifyMailView(APIView):
    def get(self, request, otp):
        user = self.get_user_otp(otp)
        if user:
            user.is_active = True
            user.verification_otp = None
            self.send_email(request, user)

            user.save()
            return Response("User Successfully verified", status=status.HTTP_200_OK)
        else:
            return Response("some thing went wrong", status=status.HTTP_400_BAD_REQUEST)

    def get_user_otp(self, otp):
        try:
            user = User.objects.get(verification_otp=otp, is_active=False)
            return user
        except User.DoesNotExist:
            return None

    def send_email(seld, request, user):
        subject = "Verification Confermation"

        message = f'Hi {user.email},\n' \
            f'Thankyou for registring and successfully verifying in our application,\n' \
            f'With Regards from Team Rohit Joshi Task Manager'

        return send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])


class LoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get('password')

        user = User.objects.filter(username=username).first()

        if user is None:
            raise AuthenticationFailed("User Not Found")

        if not user.check_password(password):
            raise AuthenticationFailed("Incorrect Password")

        response = Response()
        token = get_user_token(user)

        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=token["access_token"],
            expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )
        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
            value=token["refresh_token"],
            expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )
        response.data = {
            "message": "login successful",
            "access_token": token['access_token'],
            "refresh_token": token["refresh_token"],
        }
        response['CSRFToken'] = csrf.get_token(request)
        return response


@decorators.permission_classes([rest_permissions.IsAuthenticated])
class UserView(APIView):
    def get(self, request):
        user = request.user
        serializer = UserProfileSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


@decorators.permission_classes([rest_permissions.IsAuthenticated])
class LogoutView(APIView):
    def post(self, request):
        response = Response()
        refresh_token = request.COOKIES.get(
            settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH']
        )
        token = tokens.RefreshToken(refresh_token)
        token.blacklist()
        response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
        response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        response.delete_cookie('X-CSRFToken')
        response.delete_cookie('csrftoken')

        response['X-SCRFToken'] = None
        response.data = {
            "message": "user logout successfully"
        }
        return response
