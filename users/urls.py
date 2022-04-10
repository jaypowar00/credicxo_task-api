from django.urls import path
from . import views

# defined all the urls/paths to which the requests will be made and further process will be carried out by specified functions from views.
urlpatterns = [
    path('user/', views.user_profile),
    path('user/register', views.user_register),
    path('user/login', views.user_login),
    path('user/logout/', views.user_logout),
    path('teacher/get-all-students/', views.get_all_students),
    path('teacher/add-student/', views.add_student),
    path('teacher/delete-student/', views.delete_student),
    path('teacher/modify-student/', views.modify_student),
]
