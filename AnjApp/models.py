from django.db import models

# Create your models here.



import uuid
from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
from enum import Enum

class UserRole(models.TextChoices):
    ADMIN = 'ADMIN', 'Admin'
    MEMBER = 'MEMBER', 'Member'
    GUEST = 'GUEST', 'Guest'

class User(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)  # Hashed password
    role = models.CharField(max_length=10, choices=UserRole.choices, default=UserRole.MEMBER)
    is_active = models.BooleanField(default=True)

    def register(cls, username: str, email: str, password: str):
        # Hash the password before saving
        hashed_password = make_password(password)
        user = cls(username=username, email=email, password=hashed_password)
        user.save()
        return user
    register = classmethod(register)

    def login(cls, email: str, password: str):
        try:
            user = cls.objects.get(email=email, is_active=True)
            if check_password(password, user.password):
                # Here you would normally create and return a session or token
                return f"Session for user {user.username}"  # placeholder
            else:
                return None
        except cls.DoesNotExist:
            return None
    login = classmethod(login)

    def logout(self):
        # Placeholder method: actual logout is handled by session management
        pass

    def updateProfile(self, **data):
        for field, value in data.items():
            setattr(self, field, value)
        self.save()

    def deactivateAccount(self):
        self.is_active = False
        self.save()

    def __str__(self):
        return self.username
