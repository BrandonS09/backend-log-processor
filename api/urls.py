from django.urls import path
from . import views

urlpatterns = [
    path('api/upload/', views.FileUploadView.as_view(), name='file-upload'),
    path('api/csrf-token/', views.csrf_token_view, name='csrf_token'),
]