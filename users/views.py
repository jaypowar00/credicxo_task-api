import jwt
import json
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import IntegrityError
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from credicxo_task.settings import blackListedTokens
from .decorators import check_blacklisted_token
from .models import User, Student, Teacher
from .serializers import UserSerializer, StudentSerializer, TeacherSerializer
from .utils import generate_access_token, generate_refresh_token


@api_view(['GET'])
@check_blacklisted_token
def user_profile(request):
    """
    This function initially check whether user is logged in or not.
    is so, it then retrieves respective related data (either teacher or student)
    finally sends back to the user with Response({...}).

    @api_view(['GET']) restricts usage of only 'GET' type of http requests to this function
    @check_blacklisted_token checks for improper jwt usage (i.e. usage of logged out tokens)
    """
    user = request.user
    if not user.is_authenticated:
        return Response(
            {
                'status': False,
                'message': 'User not logged in',
            }
        )
    try:
        user = User.objects.filter(id=user.id).first()
        serialized_user = UserSerializer(user).data
        acc_type = serialized_user['account_type']
        if acc_type == 1:
            student = Student.objects.filter(user=user.id).first()
            serialized_student = StudentSerializer(student).data
            del serialized_student['user']
            serialized_user['account_type'] = 'student'
            serialized_user['details'] = serialized_student
        elif acc_type == 2:
            teacher = Teacher.objects.filter(user=user.id).first()
            serialized_teacher = TeacherSerializer(teacher).data
            del serialized_teacher['user']
            serialized_user['account_type'] = 'teacher'
            serialized_user['details'] = serialized_teacher
    except AttributeError:
        return Response(
            {
                'status': False,
                'message': 'Authorization cred missing'
            }
        )
    print(serialized_user)
    return Response(
        {
            'status': True,
            'user': serialized_user
        }
    )


@api_view(['POST'])
@permission_classes([AllowAny])
def user_register(request):
    """
        This function initially loads data from request.body which will be in form of JSON,
        by making use of the received data, new User object will be created, (if required, along with which either Teacher or Student objects will also be created)
        Depending on whether above mentioned operations get executed successfully or not, the response will be sent back.

        @api_view(['POST']) restricts usage of only 'POST' type of http requests to this function
        @permission_classes([AllowAny]) makes this function accessible for any types of user.
    """
    context = {}
    jsn: dict
    try:
        jsn = json.loads(request.body)
    except json.decoder.JSONDecodeError:
        jsn = {}
    if jsn:
        for key, value in jsn.items():
            if key != 'password':
                context[key] = value
    if not ('email' in jsn and 'username' in jsn and 'password' in jsn and 'name' in jsn and 'account_type' in jsn):
        return Response(
            {
                'status': False,
                'message': 'registration unsuccessful (required data: email, username, name, password, account_type)'
            }
        )
    try:
        UserModel = get_user_model()
        user = UserModel(
            email=jsn['email'],
            username=jsn['username'],
            name=jsn['name'],
            account_type=jsn['account_type']
        )
        user.set_password(jsn['password'])
        user.save()
        if jsn['account_type'] == 1:
            s_rollno = s_division = s_class = s_batch = phone = address = pincode = None
            if 'rollno' in jsn:
                s_rollno = jsn['rollno']
            if 'division' in jsn:
                s_division = jsn['division']
            if 'class' in jsn:
                s_class = jsn['class']
            if 'batch' in jsn:
                s_batch = jsn['batch']
            if 'phone' in jsn:
                phone = jsn['phone']
            if 'address' in jsn:
                address = jsn['address']
            if 'pincode' in jsn:
                pincode = jsn['pincode']
            student = Student(user=user, s_rollno=s_rollno, s_division=s_division, s_class=s_class,
                              s_batch=s_batch, phone=phone, address=address, pincode=pincode)
            student.save()
        elif jsn['account_type'] == 2:
            t_class = phone = address = pincode = subject = None
            if 'class' in jsn:
                t_class = jsn['class']
            if 'phone' in jsn:
                phone = jsn['phone']
            if 'address' in jsn:
                address = jsn['address']
            if 'pincode' in jsn:
                pincode = jsn['pincode']
            if 'subject' in jsn:
                subject = jsn['subject']
            teacher = Teacher(user=user, phone=phone, address=address, pincode=pincode, subject=subject, t_class=t_class)
            teacher.save()
            user.user_permissions.add(Permission.objects.get(codename="add_user"))
            user.user_permissions.add(Permission.objects.get(codename="view_user"))
            user.user_permissions.add(Permission.objects.get(codename="add_student"))
            user.user_permissions.add(Permission.objects.get(codename="delete_student"))
            user.user_permissions.add(Permission.objects.get(codename="view_student"))
            user.user_permissions.add(Permission.objects.get(codename="change_student"))
    except IntegrityError as err:
        print(str(err).split('\n')[1].split('(')[1].split(')')[0])
        dup = str(err).split('\n')[1].split('(')[1].split(')')[0]
        return Response(
            {
                'status': False,
                'message': f'{dup} already taken by another user, try again with another {dup}',
                'duplicate': dup
            }
        )
    except IndexError:
        return Response(
            {
                'status': False,
                'message': 'Duplication Found!'
            }
        )
    if jsn:
        return Response(
            {
                'status': True,
                'message': 'User created!',
                'user': context
            }
        )


@api_view(['POST'])
@permission_classes([AllowAny])
def user_login(request):
    """
           This function receives email & password from request in JSON.
           using which it performs checks with database values and generates jwt access & refresh tokens if received data is correct.
           finally it wraps everything in one Response and sends back.

           @api_view(['POST']) restricts usage of only 'POST' type of http requests to this function
           @permission_classes([AllowAny]) makes this function accessible for any types of user.
    """
    UserModel = get_user_model()
    email = request.data.get('email')
    password = request.data.get('password')
    response = Response()
    if email is None or password is None:
        return Response(
            {
                'status': False,
                'message': 'email/password fields missing!',
            }
        )
    user = UserModel.objects.filter(email=email).first()
    if user is None:
        return Response(
            {
                'status': False,
                'message': 'User not found!',
            }
        )
    if not user.check_password(password):
        return Response(
            {
                'status': False,
                'message': 'Wrong password',
            }
        )

    serialized_user = UserSerializer(user).data
    access_token = generate_access_token(user)
    refresh_token = generate_refresh_token(user)
    response.set_cookie(key='refreshtoken', value=refresh_token, httponly=True, secure=True, samesite=None)
    response.data = {
        'status': True,
        'message': 'successfully logged in',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': serialized_user,
    }
    return response


@api_view(['POST'])
def user_logout(request):
    """
           This function will simply read the jwt tokens from request and will put them in blacklist for avoiding its further future usage.
           corresponding actions result will decide the Response message of this function.

           @api_view(['POST']) restricts usage of only 'POST' type of http requests to this function
    """
    UserModel = get_user_model()
    authorization_header = request.headers.get('Authorization')
    if not authorization_header:
        return Response(
            {
                'status': False,
                'message': 'Authorization credential missing!',
            }
        )
    access_token = False
    refresh_token = False
    try:
        access_token = authorization_header.split(' ')[1]
        refresh_token = request.COOKIES.get('refreshtoken')
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        if not refresh_token:
            return Response(
                {
                    'status': True,
                    'message': 'Some Credentials not found in request. (might have already been logged out)',
                }
            )
        try:
            payload = jwt.decode(refresh_token, settings.REFRESH_SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response(
                {
                    'status': True,
                    'message': 'jwt session has already been timed out. (have been already logged out)',
                }
            )
        user = UserModel.objects.filter(id=payload['user.id']).first()
        if user is None:
            return Response(
                {
                    'status': True,
                    'message': 'user associated with credentials does not exists anymore',
                }
            )
    finally:
        if access_token in blackListedTokens and refresh_token in blackListedTokens:
            return Response(
                {
                    'status': True,
                    'message': 'already logged out!',
                }
            )
        if access_token in blackListedTokens:
            if refresh_token:
                blackListedTokens.add(refresh_token)
            return Response(
                {
                    'status': True,
                    'message': 'already logged out!',
                }
            )
        if refresh_token in blackListedTokens:
            if access_token:
                blackListedTokens.add(access_token)
            return Response(
                {
                    'status': True,
                    'message': 'already logged out!',
                }
            )
        if access_token:
            blackListedTokens.add(access_token)
        if refresh_token:
            blackListedTokens.add(refresh_token)
    return Response(
        {
            'status': True,
            'message': 'successfully logged out!',
        }
    )


@api_view(['GET'])
@check_blacklisted_token
def get_all_students(request):
    """
           This will initially check whether user is logged in or not,
           if logged in, then will confirm the requesting user is having account type of Teacher, if not corresponding message will be sent back as Response.
           If teacher user is requesting, all the list of students will be retrieved and sent back as Response

           @api_view(['GET']) restricts usage of only 'GET' type of http requests to this function
           @check_blacklisted_token checks for improper jwt usage (i.e. usage of logged out tokens)
    """
    user = request.user
    if not user.is_authenticated:
        return Response(
            {
                'status': False,
                'message': 'user not logged in'
            }
        )
    user = User.objects.filter(id=user.id).first()
    if user.account_type == 1:
        return Response(
            {
                'status': False,
                'message': 'this feature is only for teachers!'
            }
        )
    students = Student.objects.all()
    s_list = []
    for student in students:
        s_user = User.objects.filter(id=student.user.id).first()
        serialized_user = UserSerializer(s_user).data
        del serialized_user['account_type']
        s_serialized = StudentSerializer(student).data
        del s_serialized['user']
        serialized_user |= s_serialized
        s_list.append(serialized_user)
    return Response(
        {
            'status': True,
            'students': s_list
        }
    )


@api_view(['POST'])
@check_blacklisted_token
def add_student(request):
    """
           This will initially check whether user is logged in or not,
           if logged in, then will confirm the requesting user is having account type of Teacher, if not corresponding message will be sent back as Response.
           If teacher user is requesting, by making use of received data about student account to be added new user for student will be created
           and the according to its execution Response will be sent back.

           @api_view(['POST']) restricts usage of only 'POST' type of http requests to this function
           @check_blacklisted_token checks for improper jwt usage (i.e. usage of logged out tokens)
    """
    user = request.user
    if not user.is_authenticated:
        return Response(
            {
                'status': False,
                'message': 'user not logged in'
            }
        )
    user = User.objects.filter(id=user.id).first()
    if user.account_type == 1:
        return Response(
            {
                'status': False,
                'message': 'this feature is only for teachers!'
            }
        )
    jsn: dict
    try:
        jsn = request.data
    except json.decoder.JSONDecodeError:
        jsn = {}
    if not ('email' in jsn and 'username' in jsn and 'password' in jsn and 'name' in jsn
            and 'class' in jsn and 'division' in jsn and 'rollno' in jsn):
        return Response(
            {
                'status': False,
                'message': 'failed to create student account (required data: email, username, name, password, rollno, division, class)'
            }
        )
    try:
        UserModel = get_user_model()
        user = UserModel(
            email=jsn['email'],
            username=jsn['username'],
            name=jsn['name'],
            account_type=1
        )
        user.set_password(jsn['password'])
        user.save()
        s_rollno = s_division = s_class = s_batch = phone = address = pincode = None
        if 'rollno' in jsn:
            s_rollno = jsn['rollno']
        if 'division' in jsn:
            s_division = jsn['division']
        if 'class' in jsn:
            s_class = jsn['class']
        if 'batch' in jsn:
            s_batch = jsn['batch']
        if 'phone' in jsn:
            phone = jsn['phone']
        if 'address' in jsn:
            address = jsn['address']
        if 'pincode' in jsn:
            pincode = jsn['pincode']
        student = Student(user=user, s_rollno=s_rollno, s_division=s_division, s_class=s_class,
                          s_batch=s_batch, phone=phone, address=address, pincode=pincode)
        student.save()
    except IntegrityError as err:
        print(str(err).split('\n')[1].split('(')[1].split(')')[0])
        dup = str(err).split('\n')[1].split('(')[1].split(')')[0]
        return Response(
            {
                'status': False,
                'message': f'{dup} already assigned for another student, try again with another {dup}',
                'duplicate': dup
            }
        )
    except IndexError:
        return Response(
            {
                'status': False,
                'message': 'Duplication Found!'
            }
        )
    if jsn:
        return Response(
            {
                'status': True,
                'message': 'Student successfully added!'
            }
        )


@api_view(['POST'])
@check_blacklisted_token
def delete_student(request):
    """
           This will firstly check whether user is logged in or not,
           if logged in, then will confirm the requesting user is having account type of Teacher, if not corresponding message will be sent back as Response.
           If teacher user is requesting, email id will be retrieved from request and using this function will search for student.
           if student account is available then it will be deleted. And finally according to performed actions the Response will be sent.

           @api_view(['POST']) restricts usage of only 'POST' type of http requests to this function
           @check_blacklisted_token checks for improper jwt usage (i.e. usage of logged out tokens)
    """
    user = request.user
    if not user.is_authenticated:
        return Response(
            {
                'status': False,
                'message': 'user not logged in'
            }
        )
    user = User.objects.filter(id=user.id).first()
    if user.account_type == 1:
        return Response(
            {
                'status': False,
                'message': 'this feature is only for teachers!'
            }
        )
    jsn: dict
    try:
        jsn = request.data
    except json.decoder.JSONDecodeError:
        jsn = {}
    if 'email' not in jsn:
        return Response(
            {
                'status': False,
                'message': 'provide email id of student to delete respective students record!'
            }
        )
    student = Student.objects.filter(user__email=jsn['email']).first()
    if not student:
        return Response(
            {
                'status': False,
                'message': 'given email id does nto belong to any existing student accounts!'
            }
        )
    student.delete()
    return Response(
        {
            'status': False,
            'message': 'student record deleted successfully!'
        }
    )


@api_view(['POST'])
@check_blacklisted_token
def modify_student(request):
    """
           This will firstly check whether user is logged in or not,
           if logged in, then will confirm the requesting user is having account type of Teacher, if not corresponding message will be sent back as Response.
           If teacher user is requesting, all the fields for updating students will be retrieved from request.
           if email id is provided, then by making use of received data the corresponding Student account data will get updated.
           According to execution status of above operations, valid Response will be generated and sent back to user.

           @api_view(['POST']) restricts usage of only 'POST' type of http requests to this function
           @check_blacklisted_token checks for improper jwt usage (i.e. usage of logged out tokens)
    """
    user = request.user
    if not user.is_authenticated:
        return Response(
            {
                'status': False,
                'message': 'user not logged in'
            }
        )
    user = User.objects.filter(id=user.id).first()
    if user.account_type == 1:
        return Response(
            {
                'status': False,
                'message': 'this feature is only for teachers!'
            }
        )
    jsn: dict
    try:
        jsn = request.data
    except json.decoder.JSONDecodeError:
        jsn = {}
    if not ('email' in jsn):
        return Response(
            {
                'status': False,
                'message': 'failed to update student account (please provide email of student)'
            }
        )
    studentUser = User.objects.filter(email=jsn['email']).first()
    if (not studentUser) or (studentUser.account_type != 1):
        return Response(
            {
                'status': False,
                'message': 'User not found!'
            }
        )
    student = Student.objects.filter(user=studentUser.id).first()
    if not student:
        return Response(
            {
                'status': False,
                'message': 'Student data does not exists!'
            }
        )
    try:
        studentUser.name = jsn['name'] if 'name' in jsn else studentUser.name
        if 'password' in jsn:
            studentUser.set_password(jsn['password'])
        studentUser.save()
        student.s_rollno = jsn['rollno'] if 'rollno' in jsn else student.s_rollno
        student.s_division = jsn['division'] if 'division' in jsn else student.s_division
        student.s_class = jsn['class'] if 'class' in jsn else student.s_class
        student.s_batch = jsn['batch'] if 'batch' in jsn else student.s_batch
        student.phone = jsn['phone'] if 'phone' in jsn else student.phone
        student.address = jsn['address'] if 'address' in jsn else student.address
        student.pincode = jsn['pincode'] if 'pincode' in jsn else student.pincode
        student.save()
        if jsn:
            return Response(
                {
                    'status': True,
                    'message': 'Student data successfully updated!'
                }
            )
    except Exception as e:
        print(e)
        return Response(
            {
                'status': False,
                'message': 'Something went wrong! \n '+str(e)
            }
        )
