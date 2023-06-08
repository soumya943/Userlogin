from django.contrib.auth.models import User
# Serializers imports
from .serializers import *
from rest_framework import status
from .models import User
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken, SlidingToken, UntypedToken
from django.contrib.auth import authenticate
from django.contrib.auth import login,logout
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes

# Create your views here.

# ========================================== User Signup =================================================

class UserApi(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        try:
            data = request.data
            serializer = UserSerializer(data=data,partial=True) 
            # validation for duplicate email
            user_obj = User.objects.filter(email=data.get('email')).exists()
            if user_obj:
                return Response({'status': "error",'message': 'User with this email already exists, Please try a new one'},status=status.HTTP_400_BAD_REQUEST)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                user = authenticate(email=data.get('email'), password=data.get('password'))
                token = {}
                SlidingToken.for_user(user)
                RefreshToken.for_user(user)
                token["refresh"] = str(RefreshToken.for_user(user))
                token["access"] = str(RefreshToken.for_user(user).access_token)
                print(token)
                user_data=serializer.data
                user_data['accesstoken']=token['access']
                user_data["refreshtoken"]=token['refresh']
                return Response({'message': 'User Created Successfully','data': {'user': user_data}}, status=status.HTTP_201_CREATED)
                
        except Exception as e:
            print(e)
            return Response({'status': 'error', 'message': str(e)},status=status.HTTP_400_BAD_REQUEST)

class UserProfileAPI(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes=(IsAuthenticated,)

    def update(self, request, *args, **kwargs):
        return viewsets.ModelViewSet.update(self, request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        return viewsets.ModelViewSet.partial_update(self, request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        return viewsets.ModelViewSet.destroy(self, request, *args, **kwargs)
    
    def create(self, request, *args, **kwargs):
        try:
            data = request.data
            user_obj=request.user
            time=timezone.now()
            if user_obj.email_otp_expiry_time==None:
                print("12")
                return Response({'status': status.HTTP_400_BAD_REQUEST,'message': 'Please Resend the otp.'},status=status.HTTP_400_BAD_REQUEST)
            elif user_obj.email_otp_expiry_time>=time:
                print("13")
                if user_obj.email_otp==data.get('otp'):
                    print("14")
                    user_obj.email_otp=None
                    user_obj.email_otp_expiry_time=None
                    user_obj.is_email_verified=True
                    user_obj.save()
                    return Response({'status': status.HTTP_200_OK,'message': 'Your Email Verified Successfully.'},status=status.HTTP_200_OK)
                else:                
                    return Response({'status': status.HTTP_400_BAD_REQUEST,'message': 'OTP Invalid,Please Try Again.'},status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'status': status.HTTP_400_BAD_REQUEST,'message': 'Your OTP Expired..!'},status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            return Response({'status': status.HTTP_400_BAD_REQUEST,'message': str(e)},status=status.HTTP_400_BAD_REQUEST)

#================================ Login ===================================================

class LoginAPI(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = LoginSerializer

    def create(self, request, *args, **kwargs):
        data = request.data
        serializer = LoginSerializer(data=data)
        try:
            if serializer.is_valid(raise_exception=True):
                email = serializer.data['email'].lower()
                password = serializer.data['password']
                user = get_object_or_404(User, email=email)
                user = authenticate(email=email, password=password)
                if user:
                    token = {}
                    SlidingToken.for_user(user)
                    RefreshToken.for_user(user)
                    token["refresh"] = str(RefreshToken.for_user(user))
                    token["access"] = str(RefreshToken.for_user(user).access_token)
                    login(request, user)
                    serializer = UserSerializer(user)

                    userdetails = serializer.data
                    userdetails['access'] = token["access"]
                    userdetails['refresh'] = token["refresh"]
                    return Response({'status': "Success",'message': 'User login Successflly','data':userdetails},status=status.HTTP_200_OK)
                else:
                    return Response({'status': "Failed",'message': 'User account does not exist, Kindly check credentials'},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status': "Error",'message': str(e)},status=status.HTTP_400_BAD_REQUEST)
#============================================== Change Password =========================================================

class ChangeUserPasswordAPI(viewsets.ModelViewSet):
    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,)

    def patch(self, request, *args, **kwargs):
        try:
            serializer = ChangeUserPasswordSerializer(data=request.data)
            serializer.context['user'] = request.user
            serializer.is_valid()
            user = serializer.execute()
            logout(request)
            return Response({'status': status.HTTP_200_OK,'message': 'Password changed successfully,Kindly login again.','data':""},status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status': status.HTTP_400_BAD_REQUEST,'message': str(e)},status=status.HTTP_400_BAD_REQUEST)
        
#============================================== Forgot Password ============================================================
from django.core.mail import send_mail
class ForgetPasswordSendMail(APIView):
    def post(self,request):
        try:
            data = request.data['email']
            print(data,)
            try:
                user = User.objects.get(email=data)
            except:
                user = None
            if user!=None:
                uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                url = "http://localhost:3000/resetpassword/{0}/{1}".format(uidb64,token)
# please uncommit the subject,message, enail_from,recipient_list,send_mail and go to setting file configuration the mail id and password then hide the ctx  check the forget password send the mail_id
                # subject = 'Forget Password'
                # message = url
                # email_from = settings.EMAIL_HOST_USER
                # recipient_list = [data, ]
                # send_mail( subject, message, email_from, recipient_list)

                ctx = {
                        'user':  user.full_name,
                        'email' : user.email.lower(),
                        'url' : url,
                        'uid': uidb64,
                        'token':token,
                        'data1':'We received a request to reset your password!',
                        'data2':'If you did not forgot your password you can safely ignore this email.'
                }
                return Response({'status': status.HTTP_200_OK,'message': 'Please check your email.' ,data:ctx},status=status.HTTP_200_OK)
            else:
                return Response({'status': status.HTTP_400_BAD_REQUEST,'message': 'Invalid Email'},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status': status.HTTP_400_BAD_REQUEST,'message': str(e)},status=status.HTTP_400_BAD_REQUEST)

class ForgetPassword(APIView):
    def post(self,request):
        try:
            data=request.data
            uid=request.data['uid']
            token=request.data['token']
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if user:
                if not PasswordResetTokenGenerator().check_token(user, token):
                    return Response({'status': status.HTTP_400_BAD_REQUEST,'message': 'Invalid Token.'},status=status.HTTP_400_BAD_REQUEST)
                else:
                    if data['new_password']==data['confirm_password']:
                        password=data['confirm_password']
                        user.set_password(password)
                        user.save()
                        return Response({'status': status.HTTP_200_OK,'message': 'Password changed successfully!'},status=status.HTTP_200_OK)
                    elif data['new_password']!=data['confirm_password']:
                        return Response({'status': status.HTTP_400_BAD_REQUEST,'message': "Those password don't match"},status=status.HTTP_400_BAD_REQUEST)                        
            else:
                return Response({'status': status.HTTP_400_BAD_REQUEST,'message': "User not found."},status=status.HTTP_400_BAD_REQUEST)                        
        except Exception as e:
            return Response({'status': status.HTTP_400_BAD_REQUEST,'message': str(e)},status=status.HTTP_400_BAD_REQUEST)