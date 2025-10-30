from django.shortcuts import render, HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout
from django.urls import reverse
from .forms import *
from main.models import *
from django.conf import settings
import sweetify
import random as r
import smtplib
import datetime

def landingpage(request):
    departments = ['CEIT', 'CTE', 'CAS', 'COT', 'Main']
    schedules = {dep.lower(): votingschedule.objects.filter(department=dep).first() or 'No Schedule' for dep in departments}
    schedules['today'] = datetime.date.today()
    schedules['schedules'] = votingschedule.objects.all() if votingschedule.objects.exists() else []
    return render(request, 'account/landingpage.html', schedules)

def generate_otp():
    otp = "".join(str(r.randint(1, 9)) for _ in range(r.randint(5, 8)))
    return otp

def send_otp(email, otp):
    try:
        SENDER_EMAIL = settings.OTP_EMAIL
        SENDER_PASSWORD = settings.OTP_PASSWORD
        SUBJECT = "OTP Verification"
        TEXT = otp
        MESSAGE = f'Subject: {SUBJECT}\n\n{TEXT}'
        RECEIVER_EMAIL = email
        SERVER = smtplib.SMTP('smtp.gmail.com', 587)
        SERVER.starttls()
        SERVER.login(SENDER_EMAIL, SENDER_PASSWORD)
        SERVER.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, MESSAGE)
        SERVER.quit()
    except Exception as e:
        print(f"Failed to send OTP email: {e}")
        return False
    return True

def login_view(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user = authenticate(request, email=email, password=password)
        if user is not None:
            otp = generate_otp()
            user.otp = otp
            user.save()
            if send_otp(email, otp):
                request.session['email'] = email  # Save email in session to use in verify view
                sweetify.success(request, 'Check your email for verification')
                return HttpResponseRedirect(reverse('verify'))
            else:
                sweetify.error(request, 'Failed to send OTP email. Please try again.')
                return render(request, 'account/login.html', {'error': 'Failed to send OTP email. Please try again.'})
        else:
            sweetify.error(request, 'Invalid Credentials')
            return render(request, 'account/login.html', {'error': 'Invalid Credentials'})
    return render(request, 'account/login.html')

def verify(request):
    if 'email' not in request.session:
        sweetify.error(request, 'Session expired, please login again.')
        return HttpResponseRedirect(reverse('login'))

    email = request.session['email']
    user = Account.objects.get(email=email)
    otp_form = VerificationForm()

    if request.method == 'POST':
        otp_form = VerificationForm(request.POST)
        if otp_form.is_valid():
            user_otp = otp_form.cleaned_data['otp']
            if user.otp == user_otp:
                user.verified = True
                user.save()
                login(request, user)  # Log the user in after OTP verification
                sweetify.success(request, 'Login Successfully')
                return HttpResponseRedirect(reverse('home'))
            else:
                sweetify.error(request, 'OTP is incorrect!')
                return render(request, 'account/verify.html', {'error': 'OTP is incorrect!', 'otp_form': otp_form})

    return render(request, 'account/verify.html', {'otp_form': otp_form})

def register_view(request):
    Registration_Form = RegistrationForm()
    if request.method == 'POST':
        Registration_Form = RegistrationForm(request.POST)
        email = request.POST['email']
        password1 = request.POST['password']
        password2 = request.POST['password2']
        if password1 != password2:
            sweetify.error(request, 'Passwords do not match!')
            return render(request, 'account/register.html', {'error': 'Passwords do not match!', 'Registration_Form': Registration_Form})
        elif Registration_Form.is_valid():
            Registration_Form.save()
            sweetify.success(request, 'Registration Successful')
            return HttpResponseRedirect(reverse('login'))
        elif Account.objects.filter(email=email).exists():
            sweetify.error(request, 'Email already exists!')
            return render(request, 'account/register.html', {'error': 'Email already exists!', 'Registration_Form': Registration_Form})
        else:
            sweetify.error(request, 'Invalid Credentials')
            return render(request, 'account/register.html', {'error': 'Invalid Credentials', 'Registration_Form': Registration_Form})
    return render(request, 'account/register.html', {'Registration_Form': Registration_Form})

def logout_view(request):
    logout(request)
    return render(request, 'account/login.html')
