from django.shortcuts import render, redirect
from django.contrib import messages, auth
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib import messages, auth
from django.contrib.auth.models import User
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from random import randint
from django.core.mail import EmailMessage
from contacts.models import Contact
from django.shortcuts import render
from django.shortcuts import render, redirect
from django.contrib import messages, auth
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from random import randint
from django.core.mail import EmailMessage
from contacts.models import Contact
from django.shortcuts import render
from django_otp import user_has_device
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex

from captcha.fields import ReCaptchaField
from captcha.widgets import ReCaptchaV2Checkbox
from django.conf import settings
from django.contrib import messages
from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login
from captcha.widgets import ReCaptchaV2Checkbox
from captcha.fields import ReCaptchaField
from django import forms

def my_view(request):
    user_input = request.POST.get('user_input')
    bot_response = get_bot_response(user_input)
    # do something with the bot response
    ...

def profile(request):
    user = request.user
    context = {'user': user}
    return render(request, 'dashboard/profile.html', context)
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import EmailMessage
from django.shortcuts import render, redirect

def register(request):
    if request.method == 'POST':
        # Get form values
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        password2 = request.POST['password2']

        # Check if passwords match
        if password == password2:
            # Check username
            if User.objects.filter(username=username).exists():
                messages.error(request, 'The username already exists')
                return redirect('register')
            else:
                if User.objects.filter(email=email).exists():
                    messages.error(request, 'The email already exists')
                    return redirect('register')
                else:
                    # Everything passed
                    user = User.objects.create_user(
                        username=username,
                        password=password,
                        email=email,
                        first_name=first_name,
                        last_name=last_name
                    )


                    # Send welcome email
                    message = EmailMessage(
                        subject='Welcome to Nirvana!',
                        body="""Dear User,
                            Thank you for joining Nirvana! We are excited to have you as a part of our community.As a new member, you now have access to all the features and benefits that come with being a member of our site.We hope that you will find our platform useful and enjoyable, and that it will help you in achieving your goals.If you have any questions or concerns, please don't hesitate to contact us. Our support team is always ready to assist you.
                    Once again, welcome to Nirvana!
                    Best regards,
                    Nirvana!!!""",
                        from_email='from@example.com',
                        to=[user.email],
                    )
                    message.send()

                    # Login after register
                    user.save()
                    messages.success(request, 'You are now registered and can Log In')
                    return redirect('login')
        else:
            messages.error(request, 'Passwords do not match')
            return redirect('register')
    else:
        return render(request, 'accounts/register.html')




class LoginForm(forms.Form):
    # ...
    captcha = ReCaptchaField()



def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        captcha = request.POST.get('g-recaptcha-response')

        if captcha:
            form = LoginForm(request.POST)
            if form.is_valid():
                user = auth.authenticate(username=username, password=password)

                if user is not None:
                    auth.login(request, user)
                    messages.success(request, 'You are now logged in')
                    return redirect('dashboard')
                else:
                    messages.error(request, 'Invalid credentials')
                    return redirect('login')
        else:
            messages.error(request, 'Invalid reCAPTCHA. Please try again.')
            return redirect('login')
    else:
        form = LoginForm()
        return render(request, 'accounts/login.html', {'form': form})



def logout(request):
    if request.method == "POST":
        auth.logout(request)
        messages.success(request, 'You are now logged out')
        return redirect('login')


def dashboard(request):
    user_contacts = Contact.objects.order_by('-contact_date').filter(user_id=request.user.id)

    context = {
        'contacts': user_contacts
    }
    return render(request, 'accounts/dashboard.html', context)
