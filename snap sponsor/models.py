from django.db import models
import uuid, datetime
from .managers import UserManager
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin

'''
0 -> Sponsor
1 -> Sponsee
'''


class BaseModel(models.Model):
    class Meta:
        abstract = True

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def get_seconds_since_creation(self):
        return (datetime.datetime.utcnow() -
                self.created_at.replace(tzinfo=None)).seconds



class Hashtags(BaseModel):
    tag = models.CharField(max_length=100)
    point = models.IntegerField(default=0)

    class Meta:
        db_table = "tags"


class User(BaseModel,AbstractBaseUser, PermissionsMixin):

    name = models.CharField(max_length = 100)
    userType = models.IntegerField()
    url = models.URLField(null = True)
    aboutMe = models.TextField(null = True)
    profileImage = models.URLField(null=True)
    phoneNumber = models.CharField(null=True,max_length=15)
    aboutOrganisation = models.TextField(null = True)
    email = models.EmailField(max_length=150, unique=True)
    password = models.CharField(max_length=255)
    tempPass = models.CharField(max_length=255, null=True)
    deviceToken = models.CharField(max_length=100)
    deviceType = models.CharField(max_length=10)
    is_validated = models.BooleanField(default=False)
    hashtags = models.ManyToManyField(Hashtags, blank=True)
    followers = models.ManyToManyField("self",blank=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)


    def __str__(self):
        return self.email

    # create objs for management
    objects = UserManager()

    USERNAME_FIELD = 'email'

    class Meta:
        db_table = 'user'

class SubGenre(BaseModel):

    name = models.CharField(max_length=100)

    class Meta:
        db_table = "subgenre"

class Genre(BaseModel):

    name = models.CharField(max_length=100)
    subgenre = models.ManyToManyField(SubGenre, blank=True)


    class Meta:
        db_table = "supergenre"

class UserGenre(models.Model):

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    genre = models.ManyToManyField(Genre, blank=True)
    subgenre = models.ManyToManyField(SubGenre, blank=True)

class ForgotPassword(BaseModel):
    """
    A ORM Class for managing forgot password link
    """
    email = models.EmailField(max_length=150)
    code = models.IntegerField()
    is_used = models.BooleanField(default=False)
    changeCode = models.IntegerField(null=True)

    #meta class
    class Meta:
        db_table = "forgot_password"

class ValidateUser(BaseModel):

    email = models.EmailField(max_length=150)
    code = models.IntegerField()
    is_used = models.BooleanField(default=False)


class Post(BaseModel):

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    text = models.TextField(null = True)
    image = models.URLField(null = True)
    imageRatio = models.FloatField(null = True)
    venue = models.TextField(null = True)
    food = models.TextField(null = True)
    monetary = models.TextField(null = True)
    other = models.TextField(null = True)
    hashtags = models.ManyToManyField(Hashtags, blank=True)
    likesCount = models.IntegerField(default=0)
    commentsCount = models.IntegerField(default=0)

    class Meta:
        db_table = "posts"

class Likes(BaseModel):

    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)


    class Meta:
        db_table = "likes"

class Comments(BaseModel):

    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    comments = models.TextField(null=True)

    class Meta:
        db_table = "comments"

