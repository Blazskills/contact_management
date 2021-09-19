from operator import length_hint
from os import access, pathconf_names
import os
import re
import json
from flask import Blueprint, request, jsonify, Flask,url_for
from werkzeug.security import generate_password_hash, check_password_hash
from src.constants.http_status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_404_NOT_FOUND, HTTP_409_CONFLICT, HTTP_500_INTERNAL_SERVER_ERROR
import validators
from src.database import User, TokenBlocklist, db
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt, jwt_required, get_jwt_identity
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from flask_jwt_extended import JWTManager
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer , SignatureExpired
from flasgger import swag_from
from flask_marshmallow import Marshmallow
from sqlalchemy import func, desc
import phonenumbers
from flask_mail import Mail, Message
from threading import Thread
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer



app = Flask(__name__, instance_relative_config=True)
jwt = JWTManager(app)
auth = Blueprint('auth', __name__, url_prefix='/api/v1/auth')
ACCESS_EXPIRES = timedelta(hours=1)

ma = Marshmallow(app)

 # !Member schema
class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'Full_name' ,'User_name', 'Email', 'phone', 'Userid','create_at')

@auth.route('/users', methods=['GET'])
@jwt_required()
@swag_from('./docs/user/view_alluser.yaml')
def allusers():
    #View user Registered API
    All_user = User.query.order_by(desc(User.create_at)).all()
    member_schema = UserSchema(many=True)
    _Alluser = member_schema.dump(All_user)
    # SCHEMA FOR ALL QUERY
    return jsonify({'AllUsers': _Alluser})

app = Flask(__name__, instance_relative_config=True)

app.config['MAIL_SERVER']= 'premium24.web-hosting.com'
app.config['MAIL_USERNAME'] = os.environ.get('GMAIL_ID')
app.config['MAIL_PASSWORD'] = os.environ.get('APP_PASSWORD')
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
MAIL_MAX_EMAILS= None
MAIL_DEFAULT_SENDER = 'Ilesanmi Temitope'


mail = Mail(app)


# FUNCTION FOR SENDING PICTURE TO USER AND ADMIN "Peter from Mailtrap", 'peter@mailtrap.io') 
def send_email_thread(msg):
    with app.app_context():
        mail.send(msg)



def send_reset_email(email,token):
    msg = Message('Password Reset.', sender=('info@toismart.com'), recipients=[

        
        str(email),
    ])
    msg.body =f'''
    To reset your your password your password, visit the link:
    {url_for('auth.reset_token', token=token, _external =True)}

    If you did not make this request, then simply ignore this email and no change will be implimented.
    '''
    thr = Thread(target=send_email_thread, args=[msg])
    thr.start()

def get_reset_token(email, expires_sec=60):
    s = Serializer((os.environ.get('RESET_PASSWORD_CODE')), expires_sec)
    return s.dumps({'email': email}).decode('utf-8')




@auth.post("/reset_password")
@swag_from('./docs/user/reset_password.yaml')
def reset_request():
        try:
            if request.content_type != 'application/json':
                return jsonify({
                    'Messsage':
                    'Bad request, Content-type must be json type'
                }), HTTP_400_BAD_REQUEST
            request_data = request.get_json()
            if not request_data:
                return jsonify({"Messsage": "Empty request"}), HTTP_400_BAD_REQUEST
            email = request_data['email']
            if email == '':
                return jsonify({'Messsage':
                                'Fields can not be empty'}), HTTP_400_BAD_REQUEST
            validate_user = User.query.filter_by(
                Email=email).first()
            if validate_user:
                tokenz=get_reset_token(email)
                send_reset_email(email,tokenz)
                return jsonify({
                        'Message': 'An email has been sent with instructions to reset your password.'
                                           }), HTTP_200_OK
            return jsonify({'Message': 'Wrong Email'}), HTTP_404_NOT_FOUND
        except Exception as er:
         return jsonify({'Messsage':
                         er}), HTTP_400_BAD_REQUEST



def verify_reset_token(token):
    s = Serializer((os.environ.get('RESET_PASSWORD_CODE')))
    try:
        email = s.loads(token)['email']
    except:
        return None
    return email
     

@auth.post("/reset_password/<token>")
def reset_token(token):
    try:
        if request.content_type != 'application/json':
            return jsonify({
                'Messsage':
                'Bad request, Content-type must be json type'
            }), HTTP_400_BAD_REQUEST
        user = verify_reset_token(token)
        if user is None:
            return jsonify({'Message': 'That is an invalid or expired token'}), HTTP_401_UNAUTHORIZED
        useremail = User.query.filter_by(Email=user).first()
        if not useremail:
            return jsonify({'Message': 'User not found'}), HTTP_404_NOT_FOUND
        request_data = request.get_json()
        if not request_data:
                return jsonify({"Messsage": "Empty request"}), HTTP_400_BAD_REQUEST     
        Password = request_data['Password']
        if Password == '':
            return jsonify({'Messsage':
                            'Password Can not be Empty'}), HTTP_400_BAD_REQUEST
        hash_Password = generate_password_hash(Password, method="sha256")
        useremail.Password = hash_Password
        db.session.commit()
        return jsonify({
                        'Message': 'Your password has been updated! You are now able to log in'
                    }), HTTP_200_OK
    except Exception as er:
        return jsonify({'Messsage':
                        'There is an error'}), HTTP_400_BAD_REQUEST



# create user 1
@auth.post('create_user')
@swag_from('./docs/auth/register.yaml')
def create_user():
    """
        User creates an account
        User sign up details are added to the data base
        """

    try:
        if request.content_type != 'application/json':
            return jsonify({
                'Messsage':
                'Bad request, Content-type must be json type'
            }), HTTP_400_BAD_REQUEST
        request_data = request.get_json()
        if not request_data:
            return jsonify({"Messsage": "Empty request"}), HTTP_400_BAD_REQUEST

        fname = request_data['fname']
        lname = request_data['lname']
        User_name = request_data['User_name']
        Email = request_data['Email']
        phone = request_data['phone']
        Password = request_data['Password']
       
        if fname == '':
            return jsonify({'Messsage':
                            'First name is empty'}), HTTP_400_BAD_REQUEST
        if lname == '':
            return jsonify({'Messsage':
                            'Last name is empty'}), HTTP_400_BAD_REQUEST
        if User_name == '':
            return jsonify({'Messsage':
                            'Username is empty'}), HTTP_400_BAD_REQUEST

        if Email == '':
            return jsonify({'Messsage':
                            'Email is is empty'}), HTTP_400_BAD_REQUEST
        if phone == '':
            return jsonify({'Messsage':
                            'phone is is empty'}), HTTP_400_BAD_REQUEST
        if Password == '':
            return jsonify({'Messsage':
                            'Password is is empty'}), HTTP_400_BAD_REQUEST

        if not all(x.isalpha() and not x.isspace() for x in fname):
            return jsonify({
                'Messsage':
                'First Name should be alphabet and Ensure no space in between'
            }), HTTP_400_BAD_REQUEST

        if not all(x.isalpha() and not x.isspace() for x in lname):
            return jsonify({
                'Messsage':
                'Last Name should be alphabet and Ensure no space in between'
            }), HTTP_400_BAD_REQUEST
        if not isinstance(fname, str) or not isinstance(lname, str):
            return jsonify({
                'Messsage':
                'First Name and Last Name should be alphabet'
            }), HTTP_400_BAD_REQUEST

        if not User_name.isalnum() and not User_name.isspace():
            return jsonify({
                'Messsage':
                'Usernames must contain only letters and numbers and ensure no space'
            }), HTTP_400_BAD_REQUEST

        if len(str(fname)) < 3 or len(lname) < 3 or len(User_name) < 3:
            return jsonify({
                'Messsage':
                'First and Last Name and Username should be atleast 3 characters long'
            }), HTTP_400_BAD_REQUEST
        mobileno = phonenumbers.parse(phone, 'en')

        print('valid mobilenumber:' ,phonenumbers.is_valid_number(mobileno))

        checkvalid= phonenumbers.is_valid_number(mobileno)
        if checkvalid == False:
            return jsonify({'Messsage':
                                'This number is invalid.It can not be used.'}), HTTP_400_BAD_REQUEST
        phone_convert = phonenumbers.format_number(mobileno, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        print(phone_convert)
        if " " in Email:
            return jsonify({'Messsage': 'Ensure no space inbetween email'
                            }), HTTP_400_BAD_REQUEST
        if not validators.email(Email):
            return jsonify({'Messsage':
                            'Email is not valid'}), HTTP_400_BAD_REQUEST
        if len(Password) < 6:
            return jsonify({'Messsage':
                            'Password is too short'}), HTTP_400_BAD_REQUEST

        if User.query.filter_by(Email=Email).first() is not None:
            return jsonify({'Messsage':
                            'Email already taken'}), HTTP_409_CONFLICT

        if User.query.filter_by(phone=phone_convert).first() is not None:
            return jsonify({'Messsage':
                            'Phone number already taken'}), HTTP_409_CONFLICT
        if User.query.filter_by(User_name=User_name).first() is not None:
            return jsonify({'Messsage':
                            'Username  already taken'}), HTTP_409_CONFLICT
       
        fullname = fname + " " + lname
        print(fullname)
        hash_Password = generate_password_hash(Password, method="sha256")
        Registered_user = User(
            Full_name=fullname,
            User_name=User_name,
            Email=Email,
            phone=phone_convert,
            Password=hash_Password,
        )
        db.session.add(Registered_user)
        db.session.commit()
        return jsonify({
            'Message': 'Account created successfully',
            'user': {
                'Full_name': fullname,
                'Email': Email,
                'Username': User_name,
                'Phone': phone
            }
        }), HTTP_201_CREATED
        
    except Exception as e:
        return jsonify({'Messsage':
                                'Ensure your number has a country code.'}), HTTP_400_BAD_REQUEST
    
    except KeyError as e:
        return jsonify({'Error': str(e) + ' is missing'}), HTTP_400_BAD_REQUEST
    

# login user 2
@auth.post('/login_user')
@swag_from('./docs/auth/login.yaml')
def login_user():
    """
    User login if he supplies correct credentials for authentication
    token is generated and given to a user for authorization
    """
    try:
        if request.content_type != 'application/json':
            return jsonify({
                'Messsage':
                'Bad request, Content-type must be json type'
            }), HTTP_400_BAD_REQUEST
        request_data = request.get_json()
        if not request_data:
            return jsonify({"Messsage": "Empty request"}), HTTP_400_BAD_REQUEST
        emailorphone = request_data['emailorphone']
        Password = request_data['Password']
        if emailorphone == '' or Password == '':
            return jsonify({'Messsage':
                            'Fields can not be empty'}), HTTP_400_BAD_REQUEST
        user = User.query.filter_by(
            Email=emailorphone).first() or User.query.filter_by(
                phone=emailorphone).first()
        if user:
            is_pass_correct = check_password_hash(user.Password, Password)
            if is_pass_correct:
                refresh = create_refresh_token(identity=user.Userid)
                access = create_access_token(identity=user.Userid)
                return jsonify({
                    'Message': 'successfully Loged in ',
                    'user': {
                        'refresh_token': refresh,
                        'access_token': access,
                        'Full_Name': user.Full_name,
                        'Email': user.Email,
                        'Phone': user.phone,
                        'Username': user.User_name
                    }
                }), HTTP_200_OK
        return jsonify({'Message': 'Wrong credentials'}), HTTP_401_UNAUTHORIZED

    except Exception as er:
        return jsonify({'Messsage':
                        'email or password is invalid'}), HTTP_400_BAD_REQUEST



# retrive user 3
@auth.get('/Retrive_profile')
@jwt_required()
@swag_from('./docs/user/retrive_user.yaml')
def Retrive_profile():
    try:
        current_user = get_jwt_identity()
        user = User.query.filter_by(Userid=current_user).first()
        if not user:
            return jsonify({'Message': 'User not found'}), HTTP_404_NOT_FOUND
        return jsonify({
            'user': {
                'id': user.id,
                'Full_Name': user.Full_name,
                'Email': user.Email,
                'Phone': user.phone,
                'Username': user.User_name,
                'Userid': user.Userid,
                'Created_at': user.create_at
            }
        }), HTTP_200_OK
    except Exception as er:
        return jsonify({'Messsage': 'Something went wrong'+str(er)
                        }), HTTP_500_INTERNAL_SERVER_ERROR


# Update user 4
@auth.put('/Update_profile')
@jwt_required()
@swag_from('./docs/user/user_profile_update.yaml')
def Update_profile():
    current_user = get_jwt_identity()
    user = User.query.filter_by(Userid=current_user).first()
    if not user:
        return jsonify({'Message': 'User not found'}), HTTP_404_NOT_FOUND

    try:
        if request.content_type != 'application/json':
            return jsonify({
                'Messsage':
                'Bad request, Content-type must be json type'
            }), HTTP_400_BAD_REQUEST
        request_data = request.get_json()
        if not request_data:
            return jsonify({"Messsage": "Empty request"}), HTTP_400_BAD_REQUEST

        fname = request_data['fname']
        lname = request_data['lname']
        User_name = request_data['User_name']
        if fname == '':
            return jsonify({'Messsage':
                            'First name is empty'}), HTTP_400_BAD_REQUEST
        if lname == '':
            return jsonify({'Messsage':
                            'Last name is empty'}), HTTP_400_BAD_REQUEST
        if User_name == '':
            return jsonify({'Messsage':
                            'Username is empty'}), HTTP_400_BAD_REQUEST
        if not all(x.isalpha() and not x.isspace() for x in fname):
            return jsonify({
                'Messsage':
                'First Name should be alphabet and Ensure no space in between'
            }), HTTP_400_BAD_REQUEST

        if not all(x.isalpha() and not x.isspace() for x in lname):
            return jsonify({
                'Messsage':
                'Last Name should be alphabet and Ensure no space in between'
            }), HTTP_400_BAD_REQUEST
        if not isinstance(fname, str) or not isinstance(lname, str):
            return jsonify({
                'Messsage':
                'First Name and Last Name should be alphabet'
            }), HTTP_400_BAD_REQUEST

        if not User_name.isalnum() and not User_name.isspace():
            return jsonify({
                'Messsage':
                'Usernames must contain only letters and numbers and ensure no space'
            }), HTTP_400_BAD_REQUEST

        if len(str(fname)) < 3:
            return jsonify({
                'Messsage':
                'First Name should be atleast 3 characters long'
            }), HTTP_400_BAD_REQUEST
        if len(str(lname)) < 3:
            return jsonify({
                'Messsage':
                'Last Name should be atleast 3 characters long'
            }), HTTP_400_BAD_REQUEST
        if len(str(User_name)) < 3:
            return jsonify({
                'Messsage':
                'Username should be atleast 3 characters long'
            }), HTTP_400_BAD_REQUEST

        if User.query.filter_by(User_name=User_name).first() is not None:
            return jsonify({'Messsage':
                            'Username  already taken'}), HTTP_409_CONFLICT
        fullname = fname + " " + lname
        print(fullname)
        user.Full_name = fullname
        user.User_name = User_name
        db.session.commit()
        return jsonify({
            'Message': 'Profile updated successfully ',
            'user': {
                'id': user.id,
                'Full_Name': user.Full_name,
                'Email': user.Email,
                'Phone': user.phone,
                'Username': user.User_name,
                'userid': user.Userid,
                'contacts': user.contacts,
                'search_histories': user.search_histories,
                'email_histories': user.email_histories,
                'Created_at': user.create_at,
                'updated_at': user.updateed_at
            }
        }), HTTP_200_OK
    except KeyError as e:
        return jsonify({'Error': str(e) + ' is missing'}), HTTP_400_BAD_REQUEST

# Refresh token

@auth.post('/refresh_token')
@jwt_required(refresh=True)
@swag_from('./docs/auth/refresh_token.yaml')
def refresh_users_token():
    identity=get_jwt_identity()
    access=create_access_token(identity=identity)
    return jsonify({
        'access': access
    }), HTTP_200_OK



# Logout user 6
@auth.route("/logout", methods=["DELETE"])
@jwt_required()
@swag_from('./docs/auth/logout.yaml')
def logout():
    jti = get_jwt()["jti"]
    if jti:
        now = datetime.now(timezone.utc)
        db.session.add(TokenBlocklist(jti=jti, created_at=now))
        db.session.commit()
        return jsonify({'Message': 'Successfully logged out'}), HTTP_200_OK
    return jsonify({'Message': 'Something unusual occurred while trying to log you out'}), HTTP_500_INTERNAL_SERVER_ERROR



