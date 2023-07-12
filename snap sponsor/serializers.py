from rest_framework import serializers
from .models import User, Genre, SubGenre, ForgotPassword, UserGenre, ValidateUser, Post, Hashtags, Likes, Comments
from django.contrib.auth.hashers import make_password


# create user serializer
class UserSerializer(serializers.ModelSerializer):
    # class meta
    class Meta:
        model = User
        fields = '__all__'

    # validate passowrd
    def validate_password(self, str) -> str:
        """ A function to save the password for storing the values """
        return make_password(str)

class UserUpdateSerializer(serializers.ModelSerializer):
    # class meta
    class Meta:
        model = User
        fields = '__all__'

class GenreSerializer(serializers.ModelSerializer):

    class Meta:
        models = Genre
        fields = '__all__'

class SubGenreSerializer(serializers.ModelSerializer):

    class Meta:
        models = SubGenre
        fields = '__all__'

class ForgotPasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = ForgotPassword
        fields = '__all__'

class UserGenreSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserGenre
        fields = '__all__'

class ValidateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = ValidateUser
        fields = '__all__'

class PostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = '__all__'

class HashtagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hashtags
        fields = '__all__'

class LikeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Likes
        fields = '__all__'

class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comments
        fields = '__all__'