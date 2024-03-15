from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

User = get_user_model()


class RegisterUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm']

    def validate_password(self, value):
        validate_password(value)
        return value

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError({"password_confirm": "Пароли не совпадают."})
        return data

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user


class LoginUserSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            raise serializers.ValidationError("Необходимо указать логин и пароль.", code='authorization')

        # Используем authenticate для проверки учетных данных
        user = authenticate(request=self.context.get('request'), username=username, password=password)
        if user:
            if not user.is_active:
                raise serializers.ValidationError("Учетная запись не активирована.", code='authorization')
        else:
            raise serializers.ValidationError("Неверные учетные данные.", code='authorization')

        data['user'] = user
        return data


class ResendConfirmationEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    