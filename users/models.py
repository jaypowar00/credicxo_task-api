from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from django.contrib.auth.models import AbstractUser, PermissionsMixin
from django.utils import timezone


# defining custom user model (with account types: 1 for student, 2 for teacher 3 for admin)
class User(AbstractUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=150)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)

    date_joined = models.DateTimeField(default=timezone.now)
    '''
    when account is 1, in view functions, we've created new object of respective student class
    similar implementation done for teacher with account type as 2
    '''
    account_type = models.PositiveIntegerField(default=3, validators=[MinValueValidator(1), MaxValueValidator(3)])

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email


# student model with one to one relation of user model
class Student(models.Model):
    user = models.OneToOneField(User, related_name='student', on_delete=models.CASCADE)
    s_rollno = models.IntegerField(validators=[MinValueValidator(1),])
    s_division = models.CharField(max_length=10)
    s_class = models.CharField(max_length=50)
    s_batch = models.CharField(max_length=30)
    phone = models.CharField(max_length=20, default=None, blank=True, null=True)
    address = models.CharField(max_length=200, null=True, blank=True)
    pincode = models.CharField(max_length=6, null=True, default=None, blank=True)

    def __str__(self):
        return self.user.email


# teacher model with one to one relation of user model
class Teacher(models.Model):
    user = models.OneToOneField(User, related_name='teacher', on_delete=models.CASCADE)
    phone = models.CharField(max_length=20, default=None, blank=True, null=True)
    address = models.CharField(max_length=200, null=True, blank=True)
    pincode = models.CharField(max_length=6, null=True, default=None, blank=True)
    subject = models.CharField(max_length=50)
    t_class = models.CharField(max_length=50)

    def __str__(self):
        return self.user.email
