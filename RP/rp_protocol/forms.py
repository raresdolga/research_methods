from django import forms


class SessionIDForm(forms.Form):
    sessionID = forms.UUIDField()

