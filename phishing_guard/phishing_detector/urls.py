from django.urls import path
from . import views

urlpatterns = [
    path('goaway/', views.goaway, name='goaway'),
    path('analyze/', views.analyze, name='analyze'),
    path('health/', views.health, name='health'),
]