from django import forms

from .models import Hash


class HashForm(forms.ModelForm):

    class Meta:
        model = Hash
        fields = ('sha256', 'name',)
