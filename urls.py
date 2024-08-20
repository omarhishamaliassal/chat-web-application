#urls.py
from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from django.urls import path, include, reverse_lazy
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.index, name='index'),
    path('login/', views.home, name='login'),
    path('signup/', views.signup, name='signup'),
    path('logout/', views.logout_user, name='logout'),
    path('chat/<int:pk>/', views.chat_view, name='chat'),
    path('new_chat/<int:pk>', views.new_chat, name='new_chat'),
     path('load_chat/<int:chat_id>/', views.load_chat, name='load_chat'),
    path('chat/<int:chat_id>/create_voice_note/', views.create_voice_note, name='create_voice_note'),
    path('call/', views.videocall, name='call'),
    path('steg/', views.hide, name='steg'),
    path('voice_notes/<int:voice_note_id>/', views.serve_voice_note, name='serve_voice_note'),
    path('extract/', views.extract, name='extract'),
    path('edit-profile/', views.edit_profile, name='edit_profile'),
    path('record-and-send/', views.record_and_send, name='record_and_send'),
    path('password_reset/', auth_views.PasswordResetView.as_view(template_name='chat/password_reset_form.html'), name='password_reset'),
    path('password_reset_done/', auth_views.PasswordResetDoneView.as_view(template_name='chat/password_reset_done.html'), name='password_reset_done'),
    path('password_reset_confirm/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='chat/password_reset_confirm.html'), name='password_reset_confirm'),
    path('password_reset_complete/', auth_views.PasswordResetCompleteView.as_view(template_name='chat/password_reset_complete.html'), name='password_reset_complete'),
    path('payment/', views.payment, name='payment'),
    path('receive/', views.receive_voice_notes, name='receive_voice_notes'),
    path('playback/<int:voice_note_id>/', views.playback_voice_note, name='playback_voice_note'),
    path('wav/', views.embedwav, name='WAV'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

