from os import access, pathconf_names
import re
from flask import Blueprint, json, request, jsonify, Response,Flask
from werkzeug.security import generate_password_hash, check_password_hash
from src.constants.http_status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_404_NOT_FOUND, HTTP_409_CONFLICT
import validators
from src.database import User, db
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from flask_marshmallow import Marshmallow
app = Flask(__name__, instance_relative_config=True)
auth = Blueprint('auth', __name__, url_prefix='/api/v1/auth')


# ma = Marshmallow(app)
# class retriveuserSchema(ma.Schema):
#     class Meta:
#         fields = ('id', 'Full_name', 'User_name','Email', 'phone', 'Userid','create_at', 'updateed_at', 'contacts','search_histories', 'email_histories')



# user_schema = retriveuserSchema()
# users_schema = retriveuserSchema(many=True)






# @auth.get('alldataview')
# def alldataview():
#     return jsonify({'User_Type_Allowed':  users_schema.dump(User.query.all())})





@auth.post('create_user')
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
        if " " in Email:
            return jsonify({'Messsage': 'Ensure no space inbetween email'
                            }), HTTP_400_BAD_REQUEST
        if not validators.email(Email):
            return jsonify({'Messsage':
                            'Email is not valid'}), HTTP_400_BAD_REQUEST
        if len(Password) < 6:
            return jsonify({'Messsage':
                            'Password is too short'}), HTTP_400_BAD_REQUEST
        if " " in phone:
            return jsonify({
                'Messsage': 'Ensure no space inbetween phone number'
            }), HTTP_400_BAD_REQUEST
        if len(phone) < 10:
            return jsonify({
                'Messsage':
                'phone number should be atleast 10 characters long'
            }), HTTP_400_BAD_REQUEST
        if len(phone) > 11:
            return jsonify({
                'Messsage':
                'phone number should not be more than 11 characters long'
            }), HTTP_400_BAD_REQUEST

        if not re.match("[0-9]", phone):
            return jsonify({
                'Messsage':
                'phone number should not contain letters'
            }), HTTP_400_BAD_REQUEST

        if User.query.filter_by(Email=Email).first() is not None:
            return jsonify({'Messsage':
                            'Email already taken'}), HTTP_409_CONFLICT

        if User.query.filter_by(phone=phone).first() is not None:
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
            phone=phone,
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
    except KeyError as e:
        return jsonify({'Error': str(e) + ' is missing'}), HTTP_400_BAD_REQUEST






@auth.post('/login_user')
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
                        'Phone':user.phone,
                        'Username':user.User_name
                    }
                }), HTTP_200_OK
        return jsonify({'Message': 'Wrong credentials'}), HTTP_401_UNAUTHORIZED

    except Exception as er:
        return jsonify({'Messsage':
                        'email or password is invalid'}), HTTP_400_BAD_REQUEST


@auth.get('/Retrive_profile')
@jwt_required()
def Retrive_profile():
    try:
        userid =get_jwt_identity()
        user=User.query.filter_by(Userid=userid).first()
        if not user:
            return jsonify({'Message': 'User not found'}), HTTP_404_NOT_FOUND
        return jsonify({
            'user': {      'id':user.id,
                            'Full_Name': user.Full_name,
                            'Email': user.Email,
                            'Phone':user.phone,
                            'Username':user.User_name,
                            'Userid':user.Userid,
                            'Created_at':user.create_at,
                            'contacts':user.contacts,
                            'search_histories':user.search_histories,
                            'email_histories':user.email_histories
                        }}),HTTP_200_OK
    except Exception as er:
            return jsonify({'Messsage':
                            'Invalid user'}), HTTP_400_BAD_REQUEST


# @auth.post('/token/refresh')
# @jwt_required(refresh=True)
# def refresh_users_token():
#     identity=get_jwt_identity()
#     access=create_access_token(identity=identity)
#     return jsonify({
#         'access': access
#     }), HTTP_200_OK