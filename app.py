from flask import Flask, render_template, url_for, request, redirect, session
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = '465'
app.config['MAIL_USERNAME'] = 'it@hua.gr'
app.config['MAIL_PASSWORD'] = 'pass'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

class SignupForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=6, max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    password2 = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Re-enter password"})
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                'That email already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

class vehicle(db.Model):
    id = db.Column(db.Integer)
    license_plate = db.Column(db.String(10), primary_key=True)
    vehicle_type = db.Column(db.String(50), nullable=False)
    manufacturer = db.Column(db.String(50), nullable=False)
    model_name = db.Column(db.String(50), nullable=False)
    color = db.Column(db.String(50), nullable=False)
    owner = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return '<Vehicle %r>' % self.id

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                session['email'] = user.email
                return redirect(url_for('index'))
            else:
                message = 'Your email or password is incorrect!'
        else:
                message = 'Your email or password is incorrect!'

    return render_template('login.html', form=form, message=message)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    message = None
    form = SignupForm()
    if form.password.data != form.password2.data:
        message = 'Passwords must match!'
        return render_template('signup.html', form=form, message = message)

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    else:
        if  User.query.filter_by(email=form.email.data).first():
            message = 'This email is already in use!'

    return render_template('signup.html', form=form, message = message)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/', methods=['POST', 'GET'])
@login_required
def index():
    message = None
    user = User.query.filter_by(email=session['email']).first()
    vehicles = vehicle.query.filter_by(id=user.id).all()
    
    if request.method == 'POST':

        # if request.form['email_button'] == 'email':
        #     msg = Message("My vehicle registry", sender='vreg-noreply@gmail.com', recipients=["aggelos.almouti@gmail.com"])
        #     text = ''
        #     for x in vehicles:
        #         text += 'License Plate: ' + x.license_plate +", " +'Type: ' + x.vehicle_type +", " +'Manufacturer: ' + x.manufacturer +", " +'Model Name: ' + x.model_name +", " +'Color: ' + x.color +", " +'Owner: ' + x.owner + "\n"
                
        #     msg.body = str(text)
        #     mail.send(msg)
        #     sent = 'Email sent'
        #     return render_template('index.html', vehicles=vehicles, sent=sent)
            
        # elif request.form['import_form'] == 'add':

        new_vehicle = vehicle(
            id = user.id,
            license_plate = request.form['license_plate'],
            vehicle_type = request.form['vehicle_type'],
            manufacturer = request.form['manufacturer'],
            model_name = request.form['model_name'],
            color = request.form['color'],
            owner = request.form['owner']
        )

        if new_vehicle.query.filter_by(license_plate=new_vehicle.license_plate).first():
            message = 'This license plate is already in use!'
            return render_template('index.html', vehicles=vehicles, message=message)

        try:
            db.session.add(new_vehicle)
            db.session.commit()
            return redirect('/')
        except:
            return 'Error adding vehicle'

    else:
        return render_template('index.html', vehicles=vehicles)
        

@app.route('/delete/<string:license_plate>')
@login_required
def delete(license_plate):
    vehicle_to_delete = vehicle.query.get_or_404(license_plate)

    try:
        db.session.delete(vehicle_to_delete)
        db.session.commit()
        return redirect('/')
    except:
        return 'Error deleting vehicle'

@app.route('/update/<string:license_plate>', methods=['GET', 'POST'])
@login_required
def update(license_plate):
    vehicle_to_update = vehicle.query.get_or_404(license_plate)

    if request.method == 'POST':
        vehicle_to_update.vehicle_type = request.form['vehicle_type']
        vehicle_to_update.manufacturer = request.form['manufacturer']
        vehicle_to_update.model_name = request.form['model_name']
        vehicle_to_update.color = request.form['color']
        vehicle_to_update.owner = request.form['owner']

        try:
            db.session.commit()
            return redirect('/')
        except:
            return 'Error updating vehicle'

    else:
        return render_template('update.html', vehicle_to_update = vehicle_to_update)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)