from django.urls import path
from . import views

urlpatterns=[
  
  
    path('test',views.test,name="test"),
    path('main',views.main,name="main"),
    path('alert',views.alert,name="alert"),
    path("urlpredict",views.predict_view,name="predict_url")
]