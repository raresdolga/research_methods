from django import forms

class Passport(forms.Form):
  first_name = forms.CharField(label="First Name", max_length="100")
  last_name = forms.CharField(label="Last Name", max_length="100")
  pass_nr = forms.CharField(label="Passport Number", max_length="10")

class DriverLicense(forms.Form):
  first_name = forms.CharField(label="first_name", max_length="100")
  last_name = forms.CharField(label="last_name", max_length="100")
  address = forms.CharField(label="address", max_length="10")
