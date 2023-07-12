# django core libraries
import json
import pandas as pd
from random import randint
import jwt
import pymongo
from bson.json_util import dumps
import boto3
import base64
import re
import itertools
from io import BytesIO
from PIL import Image


# from django.http import HttpResponse
from django.core.mail import send_mail
from django.core.paginator import Paginator
# from django.contrib.auth.hashers import check_password
from django.conf import settings
from django.core.files.storage import FileSystemStorage


from rest_framework import generics, status, permissions, filters
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
# from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.views import TokenObtainPairView


from .models import User, ForgotPassword, ValidateUser, Post, Hashtags, Likes, Comments
from .serializers import UserSerializer, ForgotPasswordSerializer, ValidateUserSerializer, UserUpdateSerializer, \
    PostSerializer, HashtagSerializer, LikeSerializer, CommentSerializer




# response function
def responsedata(stat,message,data=None):
    if stat:
        return {
            "status":stat,
            "message":message,
            "data": data
        }
    else:
        return {
            "status":stat,
            "message":message,

        }

        
def send_email(recipient, subject, body, msg_html=None):
    """
    This method create the mail and send it to recipient.
    :param recipient: receiver of mail
    :param subject: subject line of the mail
    :param body: body of the mail
    """
    FROM = 'i.vaibhavmahajan@gmail.com'
    TO = recipient if type(recipient) is list else [recipient]
    send_mail(subject, body, FROM, TO, html_message=msg_html,
                    fail_silently=False)

# Login class
class Login(TokenObtainPairView):
    token_obtain_pair = TokenObtainPairView.as_view()

    def post(self, request, *args, **kwargs):

        if not request.data.get("email"):
            return Response(responsedata(False, "Email Id is required"), status=status.HTTP_405_METHOD_NOT_ALLOWED)

        if not request.data.get("password"):
            return Response(responsedata(False, "Password is required"), status=status.HTTP_405_METHOD_NOT_ALLOWED)

        if not User.objects.filter(email=request.data.get("email")).exists():
            return Response(responsedata(False, "No user found with this Email Id"), status=status.HTTP_404_NOT_FOUND)

        if not User.objects.get(email=request.data.get("email")).check_password(request.data.get("password")):
            return Response(responsedata(False, "Incorrect Password"), status=status.HTTP_404_NOT_FOUND)

        serializer = TokenObtainPairSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            data = serializer.validate(request.data)

            if serializer.user.is_active and serializer.user.is_validated:
                userdata = {"userID":serializer.user.uuid, "userName":serializer.user.name,
                            "emailID":serializer.user.email}
                return Response(responsedata(True, "Login Successfull", userdata),headers=data, status=200)
            else:
                validation_obj = ValidateUser.objects.get(email=serializer.user.email)
                validation_data = ValidateUser.objects.filter(email=serializer.user.email).values().first()
                try:
                    number = str(randint(1000, 9999))
                    send_email(['i.vaibhavmahajan@gmail.com', request.data.get("email")], "code for registration",
                               number)

                    validation_data['code'] = int(number)
                    validation_serializer = ValidateUserSerializer(validation_obj, data=validation_data)
                    if validation_serializer.is_valid(raise_exception=True):
                        validation_serializer.save()

                    return Response(responsedata(True, "User exists, validate please, mail send successfully"),
                                    status=status.HTTP_401_UNAUTHORIZED)

                except Exception as e:
                    print(str(e))
                    return Response(responsedata(False, "Cant send mail"), status=status.HTTP_400_BAD_REQUEST)

# class for listing and create
class UserList(generics.ListAPIView):
    """
    ORM to create and list the users
    """
    search_fields = ['name', 'email']
    filter_backends = (filters.SearchFilter,)
    queryset = User.objects.all().order_by('name')
    serializer_class = UserSerializer

    def filter_queryset(self, queryset):
        for backend in list(self.filter_backends):
            queryset = backend().filter_queryset(self.request, queryset, self)
        return queryset

    def list(self, request, **kwargs):

        queryset = self.filter_queryset(self.get_queryset())
        queryset = queryset.order_by('name')

        pagenum = request.GET.get('page', 1)
        paginator = Paginator(queryset, 10)
        if int(pagenum) > paginator.num_pages:
            return Response(responsedata(True, "No page found", []), status=status.HTTP_200_OK)

        res = paginator.page(pagenum).object_list
        serializer = UserSerializer(res, many=True)
        response_data = serializer.data

        for data in response_data:
            del data["followers"]

        return Response(responsedata(True, "user data", response_data), status=status.HTTP_200_OK)

# user registration class
class Register(APIView):
    def post(self, request):

        data = request.data
        data.update({'tempPass':data.get("password")})


        if User.objects.filter(email=data.get("email"), is_validated=True).values().exists():
            return Response(responsedata(False, "User already present"), status = status.HTTP_409_CONFLICT)

        elif User.objects.filter(email=data.get("email"), is_validated=False).values().exists():

            validation_obj = ValidateUser.objects.get(email=data.get("email"))
            validation_data = ValidateUser.objects.filter(email=data.get("email")).values().first()
            try:
                number = str(randint(1000, 9999))
                send_email(['i.vaibhavmahajan@gmail.com', request.data.get("email")], "code for registration",
                           number)

                validation_data['code'] = int(number)
                validation_serializer = ValidateUserSerializer(validation_obj, data=validation_data)
                if validation_serializer.is_valid(raise_exception=True):
                    validation_serializer.save()

                return Response(responsedata(True, "User exists, validate please, mail send successfully"), status=status.HTTP_401_UNAUTHORIZED)

            except Exception as e:
                print(str(e))
                return Response(responsedata(False, "Cant send mail"), status=status.HTTP_400_BAD_REQUEST)

        if not data.get("url").startswith("http"):
            return Response(responsedata(False, "Invalid URL"), status=status.HTTP_400_BAD_REQUEST)

        serializer = UserSerializer(data=data)
        if serializer.is_valid(raise_exception=True):

            try:
                number = str(randint(1000, 9999))
                send_email(['i.vaibhavmahajan@gmail.com', data.get("email")], "code for registration", number)

                validation_data = {
                    "email":data.get("email"),
                    "code":number
                }
                validation_serializer = ValidateUserSerializer(data=validation_data)
                if validation_serializer.is_valid(raise_exception=True):
                    validation_serializer.save()

                serializer.save()

                return Response(responsedata(True, "Mail sent successfully"), status=status.HTTP_201_CREATED)

            except Exception as e:
                print(str(e))
                return Response(responsedata(False, "Cant send Mail"), status=400)

        else:
            return Response(responsedata(False, "Something went wrong"), status=400)


# send otp class
class SendOTP(APIView):

    def post(self, request):
        validation_obj = ValidateUser.objects.get(email=request.data.get("email"))
        validation_data = ValidateUser.objects.filter(email=request.data.get("email")).values()
        try:
            number = str(randint(1000, 9999))
            send_email(['i.vaibhavmahajan@gmail.com', request.data.get("email")], "code for registration", number)

            validation_data['code'] = number
            validation_serializer = ValidateUserSerializer(validation_obj, data=validation_data)
            if validation_serializer.is_valid(raise_exception=True):
                validation_serializer.save()

            return Response(responsedata(True, "Mail Sent successfully"), status = status.HTTP_200_OK)

        except Exception as e:
            print(str(e))
            return Response(responsedata(False, "Cant send mail"),status=status.HTTP_400_BAD_REQUEST)


# class for action of one user
class UserDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    ORM for actions on user
    """

    queryset = User.objects.all()
    serializer_class = UserUpdateSerializer


class UserAction(APIView):

    def put(self, request, *args, **kwargs):

        data = request.data
        token = request.headers.get('authorization').split(" ").pop()
        decoded = jwt.decode(token, settings.SIMPLE_JWT['SIGNING_KEY'], algorithms='HS256')
        userdata = User.objects.filter(pk=decoded.get('uuid')).values().first()
        userobj = User.objects.get(pk = decoded.get("uuid"))

        if data.get("image"):
            try:
                s3 = boto3.client('s3', aws_access_key_id=settings.AWS_CONFIG['AWS_ACCESS_KEY_ID'],
                                  aws_secret_access_key=settings.AWS_CONFIG['AWS_SECRET_ACCESS_KEY'])
            except Exception as e:
                print(str(e))
                return Response(responsedata(False, "Can't connect to the database"), status=404)

            try:
                name, extension = request.FILES["image"].name.split(".")
                name = name.replace(" ", "-")

                imagedata = request.FILES["image"].read()
                encoded = base64.b64encode(imagedata)
                decoded = base64.b64decode(encoded)

                s3.put_object(Body=decoded, Bucket=settings.AWS_CONFIG['AWS_STORAGE_BUCKET_NAME'],
                              Key='{}/profileimage/{}.{}'.format(userdata.get('email'), name, extension), ACL="public-read")
                userdata['profileImage'] = 'https://snapsponsor.s3-ap-south-1.amazonaws.com/{}/profileimage/{}'.format(
                    userdata.get('email'), '{}.{}'.format(name, extension))

            except Exception as e:
                print(str(e))
                return Response(responsedata(False, "Can't Upload image"), status=400)

            if data.get("aboutMe"):
                userdata["aboutMe"] = data.gte("aboutMe")
            if data.get("aboutOrganisation"):
                userdata["aboutOrganisation"] = data.get("aboutOrganisation")
            if data.get("url"):
                userdata["url"] = data.get("url")

            serializer = UserUpdateSerializer(userobj, data = userdata)
            if serializer.is_valid(raise_exception=True):
                serializer.save()

            respdata = {"userID": serializer.data.uuid, "userName": serializer.data.name,
                        "emailID": serializer.data.email, "image":serializer.data.profileImage}

            return Response(responsedata(True, "Data inserted Successfully", respdata), status=status.HTTP_200_OK)


    def delete(self, request, *args, **kwargs):

        token = request.headers.get('authorization').split(" ").pop()
        decoded = jwt.decode(token, settings.SIMPLE_JWT['SIGNING_KEY'], algorithms='HS256')
        userdata = User.objects.filter(pk=decoded.get('uuid')).values().first()

        data = User.objects.filter(pk=userdata.get("uuid"))
        if not data.exists():
            return Response(responsedata(False, "No data found with this user"), status=404)
        data.delete()
        return Response(responsedata(True, "Data Deleted"), status=200)



# forgot password class
class ForgotPasswordRequest(APIView):
    """
    A API View Class for requesting forgot password
    """

    def post(self, request):
        # check if mobile num entered or not
        if not request.data.get('email'):
            return Response(responsedata(False, "Email ID is required"), status=406)

        # check if user exist or not for the given field
        user = User.objects.filter(email=request.data.get('email'))
        if not user.exists():
            return Response(responsedata(False, "No user found with {}".format(request.data.get('email'))), status=406)

        if ForgotPassword.objects.filter(email=request.data.get('email')).values().exists():
            ForgotPassword.objects.filter(email=request.data.get('email')).delete()

        # create a model serializer
        number = str(randint(1000, 9999))
        request.data.update({'code':number})
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            try:

                send_email(['i.vaibhavmahajan@gmail.com', request.data.get("email")], "code for password",
                           number)
                serializer.save()
                return  Response(responsedata(True, "Mail sent successfully"), status=status.HTTP_200_OK)
            except Exception as e:
                print(str(e))
                return Response(responsedata(False, "Cant send mail"), status=status.HTTP_400_BAD_REQUEST)


# validate otp
class OtpValidation(APIView):
    def post(self, request):
        if not ForgotPassword.objects.filter(email=request.data.get("email"), is_used=True).values().exists():
            if not int(ForgotPassword.objects.get(email=request.data.get("email")).code) == int(request.data.get("code")):
                return Response(responsedata(False, "Invalid code"), status=status.HTTP_403_FORBIDDEN)

            number = randint(100000, 999999)
            print(number)

            obj = ForgotPassword.objects.get(email= request.data.get("email"))
            data = ForgotPassword.objects.filter(email = request.data.get("email")).values().first()
            data["changeCode"] = number

            serializer = ForgotPasswordSerializer(obj, data=data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()

            return Response(responsedata(True, "Valid code", number), status=status.HTTP_200_OK)

        else:
            return Response(responsedata(False, "password already changed, Please login"),
                            status=status.HTTP_406_NOT_ACCEPTABLE)



# class for processing forgot password request
class ForgotPasswordChange(APIView):
    """
    API View for performing password change
    based on forgot password request
    """

    # patch method
    def patch(self, request):

        if not ForgotPassword.objects.filter(email=request.data.get("email"), is_used=True).values().exists():

            if not ForgotPassword.objects.get(email=request.data.get("email")).changeCode == int(request.data.get("code")):
                return Response(responsedata(False, "You are not authorized to change password"), status=status.HTTP_401_UNAUTHORIZED)

            if not request.data.get('password'):
                return Response(responsedata(False, "Password is required"))



            request.data['is_used'] = True
            request.data['code'] = request.data.get("code")

            # reset token
            reset_token = ForgotPassword.objects.get(email=request.data.get("email"))
            password = request.data.get('password')
            request.data.pop("password")

            # create a forgot password serializer
            forgot_password_serializer = ForgotPasswordSerializer(reset_token, data=request.data)

            if forgot_password_serializer.is_valid():
                forgot_password_serializer.save()

                # retrive user values
            user = User.objects.filter(email=request.data['email']).values().first()

            # replace password from the user
            user['password'] = password

            # create a user serializer
            user_serializer = UserSerializer(User.objects.get(email=request.data['email']), data=user)

            if user_serializer.is_valid():
                user_serializer.save()
                return Response(responsedata(True, "Password Changed successfully"), status=status.HTTP_200_OK)

        else:
            return Response(responsedata(False, "password already changed, Please login"),
                            status=status.HTTP_406_NOT_ACCEPTABLE)


class ValidateUserClass(TokenObtainPairView):
    token_obtain_pair = TokenObtainPairView.as_view()

    def post(self, request, *args, **kwargs):

        if not ValidateUser.objects.filter(email=request.data.get("email"), is_used=True):
            if not int(ValidateUser.objects.get(email=request.data.get("email")).code) == int(request.data.get("code")):
                return Response(responsedata(False, "Invalid code"), status=status.HTTP_403_FORBIDDEN)

            validation_data ={
                'email':request.data.get("email"),
                'code':request.data.get("code"),
                'is_used':True
            }
            validation_obj = ValidateUser.objects.get(email=request.data.get("email"))

            validation_serializer = ValidateUserSerializer(validation_obj, data = validation_data)
            if validation_serializer.is_valid(raise_exception=True):
                validation_serializer.save()

                user_data = User.objects.filter(email=request.data.get("email")).values().first()
                print(user_data)
                user_obj = User.objects.get(email = request.data.get("email"))

                temppassword = user_data.get("tempPass")

                user_data['is_validated'] = True
                user_data['tempPass'] = None

                user_serializer = UserUpdateSerializer(user_obj,data = user_data)
                if user_serializer.is_valid(raise_exception=True):

                    token_data = {
                        "email":request.data.get("email"),
                        "password":temppassword
                    }


                    serializer = TokenObtainPairSerializer(data=token_data)
                    if serializer.is_valid(raise_exception=True):


                        data = serializer.validate(token_data)
                        user_serializer.save()
                        userdata = {"userID": serializer.user.uuid, "userName": serializer.user.name,
                                    "emailID": serializer.user.email}
                        return Response(responsedata(True, "Register Successfull", userdata), headers=data, status=200)

                    else:
                        return Response(responsedata(False, "Can't Register"), status=400)
        else:
            return Response(responsedata(False, "User already validated, Please login"), status=status.HTTP_406_NOT_ACCEPTABLE)


class Posts(APIView):

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):

        if request.data and request.headers.get('authorization'):
            data = request.data
            token = request.headers.get('authorization').split(" ").pop()
            decoded = jwt.decode(token, settings.SIMPLE_JWT['SIGNING_KEY'], algorithms='HS256')
            userdata = User.objects.filter(pk=decoded.get('uuid')).values().first()

            if data.get("image"):
                try:
                    s3 = boto3.client('s3', aws_access_key_id=settings.AWS_CONFIG['AWS_ACCESS_KEY_ID'],
                                      aws_secret_access_key=settings.AWS_CONFIG['AWS_SECRET_ACCESS_KEY'])
                except Exception as e:
                    print(str(e))
                    return Response(responsedata(False, "Can't connect to the database"), status=404)

                try:
                    name, extension = request.FILES["image"].name.split(".")
                    name = name.replace(" ", "-")

                    imagedata = request.FILES["image"].read()
                    width, height = Image.open(BytesIO(imagedata)).size

                    data["imageRatio"] = width/height

                    encoded = base64.b64encode(imagedata)
                    decoded = base64.b64decode(encoded)

                    s3.put_object(Body=decoded, Bucket=settings.AWS_CONFIG['AWS_STORAGE_BUCKET_NAME'],
                                  Key='{}/{}.{}'.format(userdata.get('email'), name, extension), ACL="public-read")
                    data['image'] = 'https://snapsponsor.s3-ap-south-1.amazonaws.com/{}/{}'.format(
                        userdata.get('email'), '{}.{}'.format(name, extension))

                except Exception as e:
                    print(str(e))
                    return Response(responsedata(False, "Can't Upload image"), status=400)

            data["user"] = userdata.get('uuid')


            serializer = PostSerializer(data = data)

            if serializer.is_valid(raise_exception=True):
                serializer.save()

                tags = re.findall(r'#\w+', data.get("text"))

                if tags:
                    for tag in tags:
                        obj = Hashtags.objects.get_or_create(tag=tag)[0]
                        Post.objects.get(uuid=serializer.data.get("uuid")).hashtags.add(obj)

                newserializer = PostSerializer(Post.objects.get(uuid=serializer.data["uuid"]))
                return Response(responsedata(True, "Posted", newserializer.data), status=status.HTTP_201_CREATED)

            else:
                return Response(responsedata(False, "Invalid data"), status=status.HTTP_400_BAD_REQUEST)

        else:
            return Response(responsedata(False, "Data or Authorization not provided"), status=status.HTTP_401_UNAUTHORIZED)

    def get(self, request):

        # data = request.data
        token = request.headers.get('authorization').split(" ").pop()
        decoded = jwt.decode(token, settings.SIMPLE_JWT['SIGNING_KEY'], algorithms='HS256')
        userobj = User.objects.filter(pk = decoded.get("uuid"))[0]

        hashtags = userobj.hashtags.values()
        if hashtags:

            hashs = [data.get("uuid") for data in hashtags]
            res = list(Post.objects.filter(hashtags__in=hashs).distinct().order_by("-created_at").values())

            alldata = list(Post.objects.filter().distinct().values().order_by("-created_at"))
            r = list(itertools.filterfalse(lambda x: x in alldata, res))+ list(itertools.filterfalse(lambda x: x in res, alldata))
            ch = list(itertools.chain(res,r))

            pagenum = request.GET.get('page', 1)
            paginator = Paginator(ch, request.GET.get('limit', 10))
            if int(pagenum) > paginator.num_pages:
                return Response(responsedata(True,"Not enough pages",[]), status=200)

            res = paginator.page(pagenum).object_list

            for data in res:

                user = User.objects.get(pk=data.get("user"))
                del data["user"]
                del data["hashtags"]
                print(data)
                data.update({"name":user.name, "profileImage":user.profileImage, "user_id":user.uuid})

            return Response(responsedata(True, "return data", res), status=status.HTTP_200_OK)
        else:

            queryset = Post.objects.all().order_by("-created_at")
            print(queryset)
            pagenum = request.GET.get('page', 1)
            paginator = Paginator(queryset, request.GET.get('limit', 10))
            if int(pagenum) > paginator.num_pages:
                return Response(responsedata(True, "Not enough pages", []), status=200)

            res = paginator.page(pagenum).object_list
            response_data = PostSerializer(res, many=True).data

            for data in response_data:
                user = User.objects.get(pk=data.get("user"))
                del data["user"]
                del data["hashtags"]
                print(data)
                data.update({"name": user.name, "profileImage": user.profileImage, "user_id": user.uuid})

            return Response(responsedata(True, "Return Data", response_data), status=status.HTTP_200_OK)


# get hashtags
class GetHashtags(generics.ListCreateAPIView):

    search_fields = ['tag']
    filter_backends = (filters.SearchFilter,)
    queryset = Hashtags.objects.all().order_by('tag')

    def filter_queryset(self, queryset):
        for backend in list(self.filter_backends):
            queryset = backend().filter_queryset(self.request, queryset, self)
        return queryset

    def list(self, request, **kwargs):

        queryset = self.filter_queryset(self.get_queryset()).order_by("point")

        pagenum = request.GET.get('page', 1)
        paginator = Paginator(queryset, request.GET.get('limit', 10))
        if int(pagenum) > paginator.num_pages:
            return Response(responsedata(True, "Not enough pages",[]), status=200)

        res = paginator.page(pagenum).object_list
        serializer = HashtagSerializer(res, many=True)
        response_data = serializer.data

        return Response(responsedata(True, "return data", response_data), status=status.HTTP_200_OK)


# update hashtags
class UpdateHashtags(APIView):

    permission_classes = [permissions.IsAuthenticated]

    def put(self, request):

        data = request.data
        token = request.headers.get('authorization').split(" ").pop()
        decoded = jwt.decode(token, settings.SIMPLE_JWT['SIGNING_KEY'], algorithms='HS256')

        # userdata = User.objects.filter(pk=decoded.get('uuid')).values().first()
        obj = User.objects.get(pk = decoded.get('uuid'))

        obj.hashtags.clear()

        if data.get("hashtags"):
            for tag in data.get("hashtags"):
                hashobj = Hashtags.objects.get(pk = tag)
                obj.hashtags.add(hashobj)

        if data.get("follow"):
            for user in data.get("follow"):
                userobj = User.objects.get(pk=user)
                userobj.followers.add(obj)


        return Response(responsedata(True, "Tags Updated"), status=status.HTTP_200_OK)


# like post
class LikePost(APIView):
    def put(self, request, pk):

        try:
            token = request.headers.get('authorization').split(" ").pop()
            decoded = jwt.decode(token, settings.SIMPLE_JWT['SIGNING_KEY'], algorithms='HS256')

        except Exception as e:
            print(str(e))
            return Response(responsedata(False, "Invalid Token"), status=status.HTTP_401_UNAUTHORIZED)



        if not Likes.objects.filter(user = decoded.get("uuid")).exists():
            try:
                likeserializer = LikeSerializer(data={"post":pk, "user":decoded.get("uuid")})
                if likeserializer.is_valid(raise_exception=True):
                    likeserializer.save()

                postobj = Post.objects.get(pk=pk)
                postdata = Post.objects.filter(pk=pk).values().first()
                postdata['likesCount'] = postdata.get("likesCount") + 1
                postdata["user"] = postdata["user_id"]
                del postdata["user_id"]

                postserializer = PostSerializer(postobj, data=postdata)
                if postserializer.is_valid(raise_exception=True):
                    postserializer.save()

                    return Response(responsedata(True, "Liked", postdata.get("likesCount")), status=status.HTTP_200_OK)

            except Exception as e:
                print(str(e))
                return Response(responsedata(False, "No post found with this uuid"), status=status.HTTP_404_NOT_FOUND)

        else:
            try:
                postobj = Post.objects.get(pk=pk)
                postdata = Post.objects.filter(pk=pk).values().first()
                postdata['likesCount'] = postdata.get("likesCount") - 1
                postdata["user"] = postdata["user_id"]
                del postdata["user_id"]

                postserializer = PostSerializer(postobj, data=postdata)
                if postserializer.is_valid(raise_exception=True):
                    Likes.objects.filter(user=decoded.get("uuid")).delete()
                    postserializer.save()

                    return Response(responsedata(True, "Dis-liked", postdata.get("likesCount")), status=status.HTTP_200_OK)
            except Exception as e:
                print(str(e))
                return Response(responsedata(False, "No post found with this uuid"))



class CommentPost(APIView):

    def post(self,request, pk):
        try:
            token = request.headers.get('authorization').split(" ").pop()
            decoded = jwt.decode(token, settings.SIMPLE_JWT['SIGNING_KEY'], algorithms='HS256')

            if not request.data.get("comment"):
                return Response(responsedata(False, "Please write something"), status=status.HTTP_403_FORBIDDEN)

            request.data['post'] = pk
            request.data['user'] = decoded.get("uuid")

            serializer = CommentSerializer(data = request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()


        except Exception as e:
            print(str(e))
            return Response(responsedata(False, "Invalid Token"), status=status.HTTP_401_UNAUTHORIZED)

    def delete(self, request, pk):

        if Comments.objects.filter(pk=pk).exists():
            Comments.objects.filter(pk=pk).delete()
            return Response(responsedata(True, "Delete"), status=status.HTTP_200_OK)

        else:
            return Response(responsedata(False, "No post found"), status=status.HTTP_404_NOT_FOUND)



class UserProfile(APIView):
    def get(self, request):
        if request.GET.get("userId"):
            userid = request.GET.get("userId")

            userdata = User.objects.filter(pk=userid).values().first()
            followerscount = User.objects.get(pk=userid).followers.count()

            postobj = Post.objects.filter(user = userid)

            count = postobj.count()
            pagenum = request.GET.get('page', 1)
            paginator = Paginator(postobj, request.GET.get('limit', 10))
            if int(pagenum) > paginator.num_pages:
                return Response(responsedata(True, "Not enough pages", []), status=200)

            res = paginator.page(pagenum).object_list


            if postobj.exists():
                response_data = PostSerializer(res, many=True).data
                for data in response_data:
                    del data["user"]
                    del data["hashtags"]
                    print(data)
                    data.update({"name": userdata["name"], "profileImage": userdata["profileImage"],
                                 "user_id": userdata["uuid"]})
            else:
                response_data = []

            resdata ={
                "name" : userdata["name"],
                "About" : userdata["aboutMe"] if userdata["userType"] == 1 else userdata["aboutOrganisation"],
                "url" : userdata["url"],
                "Followerscount" : followerscount,
                "postCount" : count,
                "Posts": response_data
            }

            return Response(responsedata(True, "User data", resdata), status=status.HTTP_200_OK)

        elif request.headers.get("authorization"):

            token = request.headers.get('authorization').split(" ").pop()
            decoded = jwt.decode(token, settings.SIMPLE_JWT['SIGNING_KEY'], algorithms='HS256')

            userdata = User.objects.filter(pk=decoded.get("uuid")).values().first()
            followerscount = User.objects.get(pk=decoded.get("uuid")).followers.count()

            postobj = Post.objects.filter(user=decoded.get("uuid")).order_by("-created_at")

            count = postobj.count()
            pagenum = request.GET.get('page', 1)
            paginator = Paginator(postobj, request.GET.get('limit', 10))
            if int(pagenum) > paginator.num_pages:
                return Response(responsedata(True, "Not enough pages", []), status=200)

            res = paginator.page(pagenum).object_list

            if postobj.exists():
                response_data = PostSerializer(res, many=True).data
                for data in response_data:
                    del data["user"]
                    del data["hashtags"]
                    data.update({"name": userdata["name"], "profileImage": userdata["profileImage"],
                                 "user_id": userdata["uuid"]})
            else:
                response_data = []

            del userdata["password"]
            userdata.update({"Followerscount" : followerscount,
                            "postCount" : count,
                            "Posts": response_data
                             })

            return Response(responsedata(True, "User data", userdata), status=status.HTTP_200_OK)


# follow user
class FollowUser(APIView):

    def put(self, request):

        token = request.headers.get('authorization').split(" ").pop()
        decoded = jwt.decode(token, settings.SIMPLE_JWT['SIGNING_KEY'], algorithms='HS256')

        userdata = User.objects.filter(pk=decoded.get("uuid")).values().first()
        userobj = User.objects.get(pk=decoded.get("uuid"))

        if request.data.get("follow"):
            for data in request.data.get("follow"):
                userobj.followers.add(User.objects.get(pk=data))

            return Response(responsedata(True, "You are now following this person"), status=status.HTTP_200_OK)

        elif request.data.get("unfollow"):
            for data in request.data.get("unfollow"):
                userobj.followers.remove(User.objects.get(pk=data))

            return Response(responsedata(True, "Unfollowed"), status=status.HTTP_200_OK)










































































# class HitApi(APIView):
#     def get(self,request):
#
#         # connection with database
#         client = pymongo.MongoClient("mongodb+srv://snapsponsor:snapsponsor@cluster0-g7rhm.mongodb.net/test?retryWrites=true&w=majority")
#         db = client.nalin
#
#         # Taking different collections
#         countrytimeline = db.countrytimeline
#         coronadata = db.coronadata
#         globaldata = db.globaldata
#
#         # global response data
#         globalurl = "https://thevirustracker.com/free-api?global=stats"
#         globalresponse = requests.request("GET", globalurl, headers={"User-Agent": "XY"})
#
#         if globalresponse:
#             globaldata.update({},json.loads(globalresponse.text).get("results")[0],False)

        # URL for all country data
        # coronaurl = "https://covid-193.p.rapidapi.com/statistics"

        # headers = {
        #     'x-rapidapi-host': "covid-193.p.rapidapi.com",
        #     'x-rapidapi-key': "3250e01b44msh3fdc23a0e033498p1ade7djsndd1a9bfa2aed"
        #     }

        # allcountrydata = requests.request("GET", coronaurl, headers=headers)

        # # inserting all country data in database
        # if allcountrydata:
        #     insert_data = json.loads(allcountrydata.text).get("response")
        #     for data in insert_data:
        #         coronadata.update({"country":data['country']},data,True)

        # # list of all counrties
        # countrylist = json.loads(dumps(db.countrylist.find({})))

        # for code in countrylist:
        #     url = "https://thevirustracker.com/free-api?countryTimeline={}".format(code.get("abbreviation"))
        #     response = requests.request("GET", url,headers={"User-Agent": "XY"})

        #     if json.loads(response.text).get("results"):
        #         pass
        #     else:
        #         countrytimeline.update({"countrytimelinedata.info.code":code.get("abbreviation")}
        #             ,json.loads(response.text),True)

        # return Response("done")

class CountryTimeline(APIView):
    def get(self,request):
        client = pymongo.MongoClient("mongodb+srv://snapsponsor:snapsponsor@cluster0-g7rhm.mongodb.net/test?retryWrites=true&w=majority")
        db = client.nalin
        collection = db.countrytimeline

        return Response(json.loads(dumps(collection.find({"countrytimelinedata.info.code":request.GET['search']}))))

class Corona(APIView):
    def get(self,request):
        if request.GET:
            search = request.GET['search']
        else:
            search = None

        client = pymongo.MongoClient("mongodb+srv://snapsponsor:snapsponsor@cluster0-g7rhm.mongodb.net/test?retryWrites=true&w=majority")
        db = client.nalin
        collection = db.coronadata
        
        if search:
            return Response(json.loads(dumps(collection.find({"country":search}))))
        else:
            return Response(json.loads(dumps(collection.find({}))))

class Global(APIView):
    def get(self,request):

        client = pymongo.MongoClient("mongodb+srv://snapsponsor:snapsponsor@cluster0-g7rhm.mongodb.net/test?retryWrites=true&w=majority")
        db = client.nalin
        collection = db.globaldata

        showdata = json.loads(dumps(collection.find({})))[0]
        return Response(showdata)


class ReadCsv(APIView):
    def post(self, request):
        filename = pd.read_csv(request.FILES["filename"])
        myfile = request.FILES["filename"]
        name, extension = request.FILES["filename"].name.split(".")
        if extension == "csv":
            fs = FileSystemStorage(location='C:/vaibhav/study')  # defaults to   MEDIA_ROOT
            filename = fs.save(myfile.name, myfile)
            return Response("done", status=status.HTTP_202_ACCEPTED)

        return Response("nai ho paya", status=status.HTTP_203_NON_AUTHORITATIVE_INFORMATION)