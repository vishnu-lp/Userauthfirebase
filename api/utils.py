from django.contrib.auth.hashers import make_password
from rest_framework import status
# from rest_framework.authtoken.models import Token
import exceptions_utils
import messages
from serializers import UserSerializer, UserProfileSerializer
from firebase import firebase


# def fetch_token(user):
#     try:
#         # Get the goal for the specified user and return key
#         token = Token.objects.get(user_id=user.id)
#         return token.key
#     except Token.DoesNotExist:
#         raise exceptions_utils.ValidationException(messages.TOKEN_NOT_FOUND, status.HTTP_404_NOT_FOUND)


def hash_password(password):
    return make_password(password)


def create_user(data):
    user_serializer = UserSerializer(data=data)
    if user_serializer.is_valid():
        fire_base = firebase.FirebaseApplication('https://vogorentals.firebaseio.com//', None)
        user = user_serializer.save()
        result = fire_base.post('/users', user_serializer.data) #Creates an Entry in Firebase
        # token = Token.objects.create(user=user)
        keys = ['id', 'first_name', 'last_name', 'email', 'contact_no', 'created'
                ]  # data that we want to return as JSON response
        user_response = {k: v for k, v in user_serializer.data.iteritems() if k in keys}
        # user_response['token'] = token.key
        return user_response
    else:
        raise exceptions_utils.ValidationException(user_serializer.errors, status.HTTP_400_BAD_REQUEST)


def update_user(data, user):
    user_serializer = UserProfileSerializer(data=data, instance=user)
    if user_serializer.is_valid():
        fire_base = firebase.FirebaseApplication('https://vogorentals.firebaseio.com/', None)
        user_serializer.save()
        result = fire_base.get('/users', None)
        res = result.keys()
        urlkey = '' 
        for i in res: #Obtain the unique key
            if result[str(i)]['id'] == int(user.id): #replace 2 with id of the element you wish to update
                urlkey = str(i)
        rem = fire_base.patch('users/'+urlkey,user_serializer.data) #Make required changes to Firebase
        return user_serializer.data
    else:
        raise exceptions_utils.ValidationException(user_serializer.errors, status.HTTP_400_BAD_REQUEST)


def authenticate_user(user, data):
    if user:
        # token = fetch_token(user)
        user_serializer = UserProfileSerializer(user, data=data)
        if user_serializer.is_valid():
            keys = ['id', 'email']
            user_serializer_dict = {k: v for k, v in user_serializer.data.iteritems() if k in keys}
            # user_serializer_dict['token'] = token
            user_serializer_dict.update(messages.LOGIN_SUCCESSFUL)
            return user_serializer_dict
        else:
            raise exceptions_utils.ValidationException(user_serializer.errors, status.HTTP_400_BAD_REQUEST)
    else:
        raise exceptions_utils.ValidationException(messages.INVALID_EMAIL_OR_PASSWORD, status.HTTP_401_UNAUTHORIZED)


def change_password(current_password, new_password, user):
    if user.check_password(current_password):

        if current_password != new_password:
            user.set_password(new_password)
            user.is_password_changed = True
            user.save()
            resp = {'user_id': user.id}
            resp.update(messages.PASSWORD_CHANGED)
            return resp
        else:
            raise exceptions_utils.ValidationException(messages.SAME_PASSWORD, status.HTTP_406_NOT_ACCEPTABLE)
    else:
        raise exceptions_utils.ValidationException(messages.CURRENT_PASSWORD_INCORRECT,
                                                   status.HTTP_401_UNAUTHORIZED)
