from django.contrib.auth.models import Permission
from django.core.mail import EmailMessage
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

# Model imports
from .models import *
from .models import USER_TYPE
from random import randint
from datetime import timedelta
from django.utils import timezone
from django.template.loader import  get_template
from django.conf import settings


def generate_random_otp(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('full_name','id', 'email','user_type','email_otp','email_otp_expiry_time','password')

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        user.email_otp = generate_random_otp(6)
        user.email_otp_expiry_time=timezone.now()+timedelta(seconds=120)
        user.save()
        return user
    def validate(self, initial_data):
        if "password" in initial_data:
            if str(initial_data['password']).__len__() < 8:
                raise Exception('Password must be at least 8 characters.') 
        if 'first_name' in initial_data:
            initial_data['first_name'] = str(initial_data['first_name']).title()
        if 'last_name' in initial_data:
            initial_data['last_name'] = str(initial_data['last_name']).title()
        return initial_data
    

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(style={'input_type': 'password'})

# ========================================= User password reset ===========================================
class AdminResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise Exception("User does not exists.")
        return value

    def reset_password(self):
        user = User.objects.get(email=self.validated_data['email'])
        password = User.objects.make_random_password()
        body = """
                Hello {},

                Your password has been reset.
                
                Your new password is {}

                Thank you
                """.format(user.full_name, password)
        email = EmailMessage('Password Reset', body,to=[user.email, ], )
        email.send()
        user.set_password(password)
        user.save()

# ========================================= User password reset ===================================================

class ChangeUserPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)
    old_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('old_password', 'password', 'confirm_password')

    def validate(self, initial_data):
        user = self.context['user']
        print(user,'-----------------------6')
        if not user.check_password(initial_data['old_password']):
            raise Exception("Old password is incorrect.")
        if initial_data['old_password'] == initial_data['password']:
            raise Exception('Your New password must not be same as last one!')
        if initial_data['password'].__len__() < 8 or initial_data['confirm_password'].__len__() < 8 :
            raise Exception('Password must be at least 8 characters.')
        if initial_data['password'] != initial_data['confirm_password']:
            raise Exception("Password fields do not match.")
        return initial_data

    def update(self, instance, validated_data):
        instance.set_password(validated_data['password'])
        instance.save()
        return instance

    def execute(self):
        return self.update(self.context['user'], self.validated_data)