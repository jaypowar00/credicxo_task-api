from rest_framework import serializers
from .models import User, Student, Teacher

# created basic serializers for our models


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'name', 'account_type', 'date_joined']


class StudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Student
        fields = ['user', 's_rollno', 's_division', 's_class', 's_batch', 'phone', 'address', 'pincode', ]


class TeacherSerializer(serializers.ModelSerializer):
    class Meta:
        model = Teacher
        fields = ['user', 'phone', 'address', 'pincode', 'subject', 't_class', ]
