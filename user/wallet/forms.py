from django import forms

class NewCredentialForm(forms.Form):
  issuer = forms.CharField(help_text="Enter a valid issuer (default Issuer_1).")

  def get_issuer(self):
    return self.issuer