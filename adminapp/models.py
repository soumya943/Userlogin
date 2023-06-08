from django.db import models
from django.contrib.auth.models import AbstractUser,BaseUserManager
from rest_framework_simplejwt.tokens import RefreshToken

# Create your models here.

USER_TYPE = (
    ('1', 'admin'),
    ('2','solution_Provider'),
    ('3','Solution_Seeker')
    
)
AUTH_PROVIDERS = {'email': 'email'}
class UserManager(BaseUserManager):
    def create_user(self, email, full_name, user_type, password=None, username=None, **extra_fields):
        """
        Creates and saves a User with the given email and password.
        """
        if not email:
            raise ValueError('Users must have an email address')
        extra_fields.setdefault('full_name', full_name)
        extra_fields.setdefault('user_type', user_type)
        extra_fields.setdefault('is_staff', False)
        # extra_fields.setdefault('username', email)
        extra_fields.setdefault('is_superuser', False)
        user = self.model(
            email=self.normalize_email(email),
            username=self.normalize_email(email), **extra_fields)

        user.set_password(password)
        user.is_active = True
        user.save(using=self._db)
        print("USER=>", user)
        return user

    def create_superuser(self, email, password,**extra_fields):
        """
        Creates and saves a superuser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('username', email)
        extra_fields.setdefault('is_superuser', True)
        user = self.create_user(email, password=password,full_name=None,user_type=None,**extra_fields)
        user.is_active = True
        user.save(using=self._db)

        return user

class User(AbstractUser):
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=100)
    full_name = models.CharField(max_length=100)
    user_type = models.CharField(max_length=100, choices=USER_TYPE,null=True,blank=True)
    is_active = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    createdAt = models.DateField(auto_now_add=True, null=True, blank=True)
    updatedAt = models.DateField(auto_now=True, null=True, blank=True)
    email_otp = models.IntegerField(null=True)
    email_otp_expiry_time = models.DateTimeField(null=True)
    auth_provider = models.CharField(max_length=255, blank=False,null=False, default=AUTH_PROVIDERS.get('email'))

    createdAt = models.DateField(auto_now_add=True, null=True, blank=True)
    updatedAt = models.DateField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  

    objects = UserManager()

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
