# myapp/forms.py
from django import forms
from django.contrib.auth.models import User
from .models import Message,VoiceNote,WavFile

class EditUsernameForm(forms.ModelForm):
    username = forms.CharField(label='New Username', max_length=150)

    class Meta:
        model = User
        fields = ['username']


class PasswordResetForm(forms.Form):
    email = forms.EmailField()
    



class MessageForm(forms.ModelForm):
    class Meta:
        model = Message
        fields = ['body', 'audio_file']
        
        
class WavFileForm(forms.ModelForm):
    class Meta:
        model = WavFile
        fields = ['file']
