from rest_framework import serializers
from .models import User


class RegisterUserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(
        style={"input_type": "password"}, write_only=True)

    class Meta:
        model = User
        fields = "__all__"
        extra_kwargs = {
            "password": {
                "write_only": True
            }
        }

    def save(self, validated_data):
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            is_admin=False,
            is_active=False
        )

        password = validated_data['password']
        confirm_password = validated_data['confirm_password']

        if password != confirm_password:
            raise serializers.ValidationError("Password did not match")

        user.set_password(password)
        user.verification_otp = generate_otp()
        user.save()
        return user


def generate_otp():
    return 123456


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
