from django.contrib import admin
from.models import User, Teacher, Student

# adding user defined models into admin panel
admin.site.register(User)
admin.site.register(Student)
admin.site.register(Teacher)
