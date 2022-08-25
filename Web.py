from flask import Flask,render_template,request,redirect,url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import create_access_token,JWTManager
import hashlib
from flask_login import LoginManager, UserMixin,login_required, login_user, logout_user, current_user
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import json,smtplib,datetime


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
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True)
    username = db.Column(db.String(100))
    password_hash = db.Column(db.String(200))
    
login = LoginManager()
login.init_app(app)
login.login_view = '/'

@login.user_loader
def load_user(id):
    return users.query.get(int(id))

@app.route("/",methods=['POST','GET'])
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
        if users.query.filter_by(email=email).first():
           msg = MIMEMultipart('alternative')
           msg['Subject'] = "Reset Password"
           msg['From'] = email
           msg['To'] = params['gmail-user']
           expires = datetime.timedelta(hours=1)
           reset_token = create_access_token(str(users.id), expires_delta=expires)
           recover_url = url_for('Reset',email=email,token=reset_token,_external=True)
           html = render_template('rest-password.html',recover_url=recover_url)
           part2 = MIMEText(html, 'html')
           msg.attach(part2)
           mail = smtplib.SMTP('smtp.gmail.com', 587)
           mail.ehlo()
           mail.starttls()
           mail.login(params['gmail-user'], params['gmail-password'])
           mail.sendmail(params['gmail-user'], email, msg.as_string())
           mail.quit()
           error2= 'Email Send Successfully!'
           return render_template('forgetpassword.html',error2=error2),404           
        else:
            error1 = 'Alert! invalid email address'
            return render_template('forgetpassword.html',error1=error1),404
    return render_template('forgetpassword.html'),404

@app.route("/resetpassword/<string:email>/<token>",methods=['POST','GET'])
def Reset(token,email):
    if current_user.is_authenticated:
        return redirect('/Main')
    if request.method=='POST':
        user = users.query.filter_by(email=email).first()
        password = request.form.get('password')
        password = password+salt
        h = hashlib.md5(password.encode())
        user.password_hash = h.hexdigest()
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('forgetpassword1.html',token=token,email=email)

@app.route('/Main')
@login_required
def Main():
    return render_template('Main.html')
 
  
@app.route("/logout",methods=['POST','GET'])
def logout():
    logout_user()
    return redirect(url_for('Main'))


if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=8080)