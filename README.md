# Credicxo_Task-API
This repo is for showcasing submission task of Credicxo Tech Pvt Ltd's internship

___

## Initalization + Execution Steps:
1. create a virtual environment, and open command prompt in it.
2. run `pip install` to install all required packages.
3. run `python manage.py makemigrations` in directory where manage.py is located.
4. run `python manage.py migrate` to migrate all the changes onto your postgresql database.
5. [Optional] before migration commands, make sure you change the database configuration settings in [settings.py](https://github.com/jaypowar00/credicxo_task-api/blob/master/credicxo_task/settings.py#L80-L94)
6. [Optional] you can also add your allowed origins in list of `CORS_ALLOWED_ORIGINS` & `CSRF_TRUSTED_ORIGINS` in [settings.py](https://github.com/jaypowar00/credicxo_task-api/blob/master/credicxo_task/settings.py#L132-L142)

## Routes provided by this API:
1. `/user/`:  
    - This route will return information of logged in user.
    - reuired to add HEADER in the `get` request with key as `Authorization` & value as `Token <access_token>`.  
    Note that, replace `<access_token>` with your received token after successful login.

2. `/user/register`:
    - This route is used for registering new account of any mentioned types (1.Student, 2.Teacher, 3.Admin).
    - it requires some JSON data to be parsed with the `post` request. below are given fields that are to be added with the request in JSON:  
      1. `email`: String
      2. `username`: String
      3. `password`: String
      4. `name`: String
      5. `account_type`: Integer
      6. `class`: String (required when account_type = 1 or 2)
      7. `phone`: String (required when account_type = 1 or 2)
      8. `address`: String (required when account_type = 1 or 2)
      9. `pincode`: String (required when account_type = 1 or 2)
      10. `subject`: String (required when account_type = 2)
      11. `division`: String (required when account_type = 1)
      12. `batch`: String (required when account_type = 1)
      13. `rollno`: Integer (required when account_type = 1)
    #### Teacher Account Regitration (JSON data) example:
      ```
        {
          "email": "teacher1@gmail.com",
          "username": "teacher1",
          "password": "teacher1",
          "name": "Teacher 1",
          "account_type": 2,
          "class": "B.Tech",
          "phone": "+911234123198",
          "address": "ABC, near xyz colony",
          "pincode": "416002",
          "subject": "Python"
        }
      ```
    #### Student Account Regitration (JSON data) example:
      ```
        {
            "email": "student4@gmail.com",
            "username": "student4",
            "password": "student4",
            "name": "Student 4",
            "account_type": 1,
            "class": "B.Tech",
            "division": "B",
            "batch": "B2",
            "rollno": 20,
            "phone": "+911234123198",
            "address": "ABC, near xyz colony",
            "pincode": "416002"
        }
      ```

3. `/user/login`:
    - This route performs login of user and returns jwt access_token & refresh_token along with user details.
    - This route requires following json fields with `post` request:
        1. `email`: String
        2. `password`: String
    #### Teacher login request example:
    ```
      {
          "email": "teacher1@gmail.com",
          "password": "teacher1"
      }
    ```

4. `/user/logout/`:
    - After requesting to this route along with HEADER set with access_token, the user will get logged out.
    - set HEADER of this `post` request with key `Authorization` & value `Token <access_token>`

5. `/teacher/get-all-students/`:
    - This route is only access by logged in user which are of type Teacher. (Student user won't be able to request to this route).
    - This route returns list of all the Student accounts.
    - set HEADER of this `get` request with key `Authorization` & value `Token <access_token>`

6. `/teacher/add-student/`:
    - `post` type of request.
    - This route is only access by logged in user which are of type Teacher. (Student user won't be able to request to this route).
    - This rote is used to create/add new Student accounts. It requires same type of attributes which were required for `Regitration of Student` as in `/user/register` route.
    - - set HEADER of this `get` request with key `Authorization` & value `Token <access_token>`

7. `/teacher/delete-student/`:
    - This route is only access by logged in user which are of type Teacher. (Student user won't be able to request to this route).
    - This route is used to delete Student account based on recieved `email` of student from `post` request.
    - set HEADER of this `get` request with key `Authorization` & value `Token <access_token>`

8. `/teacher/modify-student/`:
    - `post` type of request.
    - This route is only access by logged in user which are of type Teacher. (Student user won't be able to request to this route).
    - This rote is used to modify/update existing Student account. It requires same type of attributes which were required in `/teacher/add-student/` route.
    - in this route, `email` must be provided with request, and if Student account with provided 'email' is not found, corresponding Response is sent back to user.
    - - set HEADER of this `get` request with key `Authorization` & value `Token <access_token>`

___

## Extras / References:

This project makes use of:
1. [JWT Authentication for token-based authentications of user](https://www.django-rest-framework.org/api-guide/authentication/#json-web-token-authentication).
2. [Custom Authentication](https://docs.djangoproject.com/en/4.0/topics/auth/customizing/#writing-an-authentication-backend).
3. [Custom User Model](https://docs.djangoproject.com/en/4.0/topics/auth/customizing/#specifying-a-custom-user-model)
4. [CORSHEADER](https://pypi.org/project/django-cors-headers/) & [CSRF Settings](https://docs.djangoproject.com/en/4.0/ref/csrf/) [Optional for localhost execution, but required when deploying apis to work correctly]

___

This concludes the Initialization, Execution & Usage of this Task API project.  
Thank you.
