from datetime import datetime

from drf_spectacular.utils import extend_schema

from .utils import send_confirmation_email
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import views
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser

from .serializers import RegisterUserSerializer, LoginUserSerializer, ResendConfirmationEmailSerializer


@extend_schema(
    description='Этот эндпоинт предназначен для регистрации пользователей.'
)
class RegisterUserView(views.APIView):
    serializer_class = RegisterUserSerializer
    send_confirmation_email = send_confirmation_email

    def post(self, request, *args, **kwargs):
        serializer = RegisterUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            self.send_confirmation_email(user)
            return Response({'message': 'Пожалуйста, завершите процесс регистрации, подтвердив его по электронной'
                                        ' почте в течение 5 минут.'},
                            status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    description='Этот эндпоинт предназначен для подтверждения адреса электронной почты.',
    responses={200: {'description': 'Подтверждение адреса электронной почты прошла успешно.'}}
)
class ConfirmEmailView(views.APIView):

    def get(self, request, token):
        try:
            decoded_token = RefreshToken(token)
            user_id = decoded_token['user_id']
            user = CustomUser.objects.get(id=user_id)
            exp_timestamp = decoded_token['exp']
            exp_datetime = datetime.fromtimestamp(exp_timestamp, timezone.utc)
            if exp_datetime < timezone.now():
                return Response({'message': 'Срок действия ссылки подтверждения истек.'},
                                status=status.HTTP_400_BAD_REQUEST)
            user.is_active = True
            user.save()
            return Response({'message': 'Подтверждение адреса электронной почты прошла успешно.'}, status=status.HTTP_200_OK)
        except TokenError:
            return Response({'message': 'Ошибка при обработке токена.'}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response({'message': 'Пользователь не найден.'}, status=status.HTTP_404_NOT_FOUND)


@extend_schema(
    description='Этот эндпоинт предназначен для повторной отправки письма с запросом подтверждения '
                'адреса электронной почты.'
)
class ResendConfirmationEmailView(views.APIView):
    permission_classes = [AllowAny]
    serializer_class = ResendConfirmationEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = ResendConfirmationEmailSerializer(data=request.data)

        if serializer.is_valid():
            try:
                user = CustomUser.objects.get(email=serializer.validated_data['email'])
            except ObjectDoesNotExist:
                return Response({'detail': 'Не найдено учетной записи с указанными данными.'},
                                status=status.HTTP_404_NOT_FOUND)

            if user.is_active:
                return Response({'detail': 'Почта уже подтверждена.'}, status=status.HTTP_400_BAD_REQUEST)

            send_confirmation_email(self, user)
            return Response({'message': 'Повторное письмо с подтверждением отправлено.'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    description='Этот эндпоинт предназначен для входа пользователя в систему.'
)
class LoginUserView(views.APIView):
    serializer_class = LoginUserSerializer

    def post(self, request, *args, **kwargs):
        serializer = LoginUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            refresh = RefreshToken.for_user(user)
            access = str(refresh.access_token)

            return Response({'user_id': user.id, 'access': access, 'refresh': str(refresh)},
                            status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)


