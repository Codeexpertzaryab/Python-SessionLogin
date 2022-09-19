from flask import Flask,render_template,request,redirect,url_for,session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import create_access_token,JWTManager,decode_token
import hashlib,time
from flask_login import LoginManager, UserMixin,login_required, login_user, logout_user, current_user
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import json,smtplib,datetime
import flask,requests
import flask_login

with open('conf.json','r') as c:
    params = json.load(c)["param"]

salt = 'hello'
local_server = True
app = Flask(__name__)
jwt = JWTManager(app)

if(local_server==True):
    app.config['SQLALCHEMY_DATABASE_URI']=params['local_server']
else:
    app.config['SQLALCHEMY_DATABASE_URI']=params['Production_server']    

app.secret_key=params['SECRET_KEY']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)
class users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True)
    username = db.Column(db.String(100))
    password_hash = db.Column(db.String(200))

class Child(UserMixin, db.Model):
    __tablename__ = "child"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True)
    username = db.Column(db.String(100))
    onlinest = db.Column(db.Integer)
    person_id = db.Column(db.Integer,db.ForeignKey("users.id"))

    
login = LoginManager()
login.init_app(app)
login.login_view = "/login"

@login.user_loader
def load_user(id):
    return users.query.get(int(id))

@app.route("/login",methods=['POST','GET'])
def login():
    if current_user.is_authenticated:
        return redirect('/Main')
    error1 = None
    error2 = None
    error3 = None
    if(request.method=="POST"):
        if request.form['submit_button'] == 'SignIn':
             email = request.form.get('EmailCheck')
             userpass = request.form.get('PasswordCheck')
             userpass = userpass + salt
             h = hashlib.md5(userpass.encode())
             user = users.query.filter_by(email = email).first()
             if user is not None and user.password_hash == h.hexdigest():
                    x = 1
                    c=Child.query.filter_by(person_id=user.id).first()
                    if c==None:
                        c2=Child(person_id=user.id,email=user.email,username=user.username)
                        db.session.add(c2)
                        db.session.commit()
                        c=Child.query.filter_by(person_id=user.id).first()
                        c.onlinest=x
                        db.session.commit()
                        login_user(user)
                        return redirect('/Main')
                    else:
                        c=Child.query.filter_by(person_id=user.id).first()
                        c.onlinest=x
                        db.session.commit()
                        login_user(user)    
                    return redirect('/Main')
             else:
               error3 = 'Warning! Invalid Credentials'
        elif request.form['submit_button'] == 'SignUp':
             if current_user.is_authenticated:
                return redirect('/Main')
             namez = request.form.get('Name')
             username = request.form.get('email') 
             passwords = request.form.get('password')
             if users.query.filter_by(email=username).first():
                error1='Alert! email already exist'
             else:
                passwords = passwords+salt
                h = hashlib.md5(passwords.encode())
                user = users(email=username, username=namez,password_hash=h.hexdigest())
                db.session.add(user)
                db.session.commit()
                error2='Welcome! record addded please login'
    return render_template('loginform.html',error1=error1,error2=error2,error3=error3),404

@app.route("/resetpassword",methods=['POST','GET'])
def forgetpassword():
    if current_user.is_authenticated:
        return redirect('/Main')
    error1 = None
    error2 = None
    if request.method=='POST':
        email = request.form.get('email')
        captcha_response = request.form['g-recaptcha-response']
        if users.query.filter_by(email=email).first():
            if is_human(captcha_response):
                getid = users.query.filter_by(email=email).first()
                msg = MIMEMultipart('alternative')
                msg['Subject'] = "Reset Password"
                msg['From'] = email
                msg['To'] = params['gmail-user']
                expires = datetime.timedelta(minutes=3)
                reset_token = create_access_token(str(getid.id), expires_delta=expires)
                url = request.host_url + 'resetpassword/'
                recover_url = url+reset_token
                print(recover_url)
                html = render_template('rest-password.html',url=recover_url)
                part2 = MIMEText(html, 'html')
                msg.attach(part2)
                mail = smtplib.SMTP('smtp.gmail.com', 587)
                mail.ehlo()
                mail.starttls()
                mail.login(params['gmail-user'], params['gmail-password'])
                mail.sendmail(params['gmail-user'], email, msg.as_string())
                mail.quit()
                error2= 'Email Send Successfully!'
            else:
                error1 = 'Captacha Failed !'
            return render_template('forgetpassword.html',error2=error2,error1=error1),404           
        else:
            error1 = "Alert! email address doesn't exist"
            return render_template('forgetpassword.html',error1=error1),404
    return render_template('forgetpassword.html'),404

@app.route("/resetpassword/<token>",methods=['POST','GET'])
def Reset(token):
    if current_user.is_authenticated:
        return redirect('/Main')
    if request.method=='POST':
        user_id = decode_token(token)['sub']
        user = users.query.filter_by(id=user_id).first()
        password = request.form.get('password')
        password = password+salt
        h = hashlib.md5(password.encode())
        user.password_hash = h.hexdigest()
        db.session.commit()
        return redirect (url_for('login'))
    return render_template('forgetpassword1.html',token=token)

@app.route('/Main')
@login_required
def Main():
    return render_template('Main.html')

@app.route('/')
def Main1():
    return render_template('Main1.html')

@app.route('/home')
@login_required
def Home():
    return render_template('home.html')

@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    return render_template('index.html')

@app.route("/admin",methods=['POST','GET'])
def admin():
    c=Child.query.all()
    return render_template('admin.html',c=c),404
 

@app.route("/logout",methods=['POST','GET'])
def logout():
        x=0
        c=Child.query.filter_by(person_id=current_user.id).first()
        c.onlinest=x
        db.session.commit()
        logout_user()
        return redirect(url_for('login'))      

@app.before_request
def before_request():
    flask.session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(days=365)
    flask.session.modified = True
    flask.g.user = flask_login.current_user
        
   

def is_human(captcha_response):
    secret = '6LcSdAMiAAAAAOPQy2ms-Qr9TEnLcjV26jbyDqcU'
    payload = {'response':captcha_response, 'secret':secret}
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", payload)
    response_text = json.loads(response.text)
    return response_text['success']



if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=8080)