from datetime import date
from flasgger.utils import swag_from
from flask import Flask
import re
from src.auth import create_user
from src.database import Contact, User
from flask import Blueprint, request, jsonify
from src.constants.http_status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_204_NO_CONTENT, HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_409_CONFLICT, HTTP_500_INTERNAL_SERVER_ERROR, HTTP_507_INSUFFICIENT_STORAGE
import validators
from src.database import Contact, db
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_msearch import Search
contact = Blueprint('contact', __name__, url_prefix='/api/v1/contact')
app = Flask(__name__, instance_relative_config=True)

# Add new contact
@contact.post('/Add_contact')
@jwt_required()
@swag_from('./docs/contact/add_contact.yaml')
def Add_contact():
    try:
        if request.content_type != 'application/json':
            return jsonify({
                'Messsage':
                'Bad request, Content-type must be json type'
            }), HTTP_400_BAD_REQUEST
        request_data = request.get_json()
        if not request_data:
            return jsonify({"Messsage": "Empty request"}), HTTP_400_BAD_REQUEST

        current_user = get_jwt_identity()
        user = User.query.filter_by(Userid=current_user).first()
        if not user:
            return jsonify({'Message':
                            'Sorry, User can not found'}), HTTP_404_NOT_FOUND
        contacts_count = Contact.query.filter_by(User_id=current_user).count()
        if contacts_count >= 5:
            return jsonify({
                'Message':
                'You have exceeded your contact storage space of {} '.format(
                    contacts_count) + 'Kindly free some space'
            }), HTTP_507_INSUFFICIENT_STORAGE
        if request.method == 'POST':
            fname = request_data['fname']
            lname = request_data['lname']
            Email = request_data['Email']
            Phone = request_data['Phone']
            day = request_data['day']
            month = request_data['month']
            year = request_data['year']
            if fname == '':
                return jsonify({'Messsage':
                                'First name is empty'}), HTTP_400_BAD_REQUEST
            if lname == '':
                return jsonify({'Messsage':
                                'Last name is empty'}), HTTP_400_BAD_REQUEST

            if Email == '':
                return jsonify({'Messsage':
                                'Email is is empty'}), HTTP_400_BAD_REQUEST

            if not validators.email(Email):
                return jsonify({'Messsage':
                                'Email is not valid'}), HTTP_400_BAD_REQUEST
            if Phone == '':
                return jsonify({'Messsage':
                                'phone is is empty'}), HTTP_400_BAD_REQUEST

            if " " in Phone:
                return jsonify({
                    'Messsage':
                    'Ensure no space inbetween phone number'
                }), HTTP_400_BAD_REQUEST
            if not re.match("[0-9]", Phone):
                return jsonify({
                    'Messsage':
                    'phone number should not contain letters'
                }), HTTP_400_BAD_REQUEST
            if len(Phone) < 10:
                return jsonify({
                    'Messsage':
                    'phone number should be atleast 10 characters long'
                }), HTTP_400_BAD_REQUEST
            if len(Phone) > 11:
                return jsonify({
                    'Messsage':
                    'phone number should not be more than 11 characters long'
                }), HTTP_400_BAD_REQUEST

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

            fullname = fname + " " + lname
            if not isinstance(day, int):
                return jsonify({'Messsage':
                                'day is not a number'}), HTTP_400_BAD_REQUEST
            if not isinstance(month, int):
                return jsonify({'Messsage':
                                'month is not a number'}), HTTP_400_BAD_REQUEST
            if not isinstance(year, int):
                return jsonify({'Messsage':
                                'year is not a number'}), HTTP_400_BAD_REQUEST
            dob = date(year, month, day)
            if Contact.query.filter_by(Email=Email,
                                       User_id=current_user).first():
                return jsonify({'error':
                                'email already exists'}), HTTP_409_CONFLICT
            if Contact.query.filter_by(Phone=Phone,
                                       User_id=current_user).first():
                return jsonify({'error':
                                'Phone already exists'}), HTTP_409_CONFLICT
            if Contact.query.filter_by(Full_name=fullname,
                                       User_id=current_user).first():
                return jsonify({'error':
                                'fullname already exists'}), HTTP_409_CONFLICT

            contact = Contact(Full_name=fullname,
                              Email=Email,
                              Phone=Phone,
                              Birthday=dob,
                              User_id=current_user)
            db.session.add(contact)
            db.session.commit()

            return jsonify({
                'id': contact.id,
                'Email': contact.Email,
                'Phone': contact.Phone,
                'Birthday': contact.Birthday,
                'Userid': contact.User_id,
                'created_at': contact.Create_at,
                'updated_at': contact.Updateed_at,
            }), HTTP_201_CREATED
    except KeyError as e:
        return jsonify({'Error':
                        str(e) + ' is the problem'}), HTTP_400_BAD_REQUEST
    except Exception as er:
        return jsonify({'Messsage': 'Something went wrong' + str(er)
                        }), HTTP_500_INTERNAL_SERVER_ERROR


# view auth user contact list
@contact.get('/My_contacts')
@jwt_required()
@swag_from("./docs/contact/contactlist.yaml")
def My_contacts():
    current_user = get_jwt_identity()
    # contacts = Contact.query.filter_by(User_id=current_user).all()
    # api/v1/contact/My_contacts to view total contact of a user in 10 default
    # api/v1/contact/My_contacts?page=2 goto next page
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    contacts = Contact.query.filter_by(User_id=current_user).paginate(
        page=page, per_page=per_page)
    data = []
    for contact in contacts.items:
        data.append({
            'id': contact.id,
            'Email': contact.Email,
            'Phone': contact.Phone,
            'Birthday': contact.Birthday,
            'Userid': contact.User_id,
            'created_at': contact.Create_at,
            'updated_at': contact.Updateed_at,
        })
        meta = {
            "page": contacts.page,
            'pages': contacts.pages,
            'total_count': contacts.total,
            'prev_page': contacts.prev_num,
            'next_page': contacts.next_num,
            'has_next': contacts.has_next,
            'has_prev': contacts.has_prev,
        }
    return jsonify({'data': data, "meta": meta}), HTTP_200_OK


# View the all contact available
@contact.get('/view_contact')
@jwt_required()
@swag_from("./docs/contact/view-all-contact.yaml")
def view_contact():
    contacts_count = Contact.query.count()
    All_contacts = Contact.query.all()
    data = []
    for contact in All_contacts:
        data.append({
            'id': contact.id,
            'Email': contact.Email,
            'Phone': contact.Phone,
            'Birthday': contact.Birthday,
            'Userid': contact.User_id,
            'created_at': contact.Create_at,
            'updated_at': contact.Updateed_at,
        })
    return jsonify({
        'All Contact': data,
        'Total Contact Stored': contacts_count
    }), HTTP_200_OK


# Update user contact. User can only update his/her contact lsit
@contact.put('/<int:id>')
@jwt_required()
@swag_from("./docs/contact/update_contact.yaml")
def editcontact(id):
    try:
        if request.content_type != 'application/json':
            return jsonify({
                'Messsage':
                'Bad request, Content-type must be json type'
            }), HTTP_400_BAD_REQUEST
        request_data = request.get_json()
        if not request_data:
            return jsonify({"Messsage": "Empty request"}), HTTP_400_BAD_REQUEST

        current_user = get_jwt_identity()
        contact = Contact.query.filter_by(User_id=current_user, id=id).first()
        if not contact:
            return jsonify({'Message': 'Sorry, Contact can not found'
                            }), HTTP_404_NOT_FOUND
        fname = request_data['fname']
        lname = request_data['lname']
        Email = request_data['Email']
        Phone = request_data['Phone']
        day = request_data['day']
        month = request_data['month']
        year = request_data['year']
        if fname == '':
            return jsonify({'Messsage':
                            'First name is empty'}), HTTP_400_BAD_REQUEST
        if lname == '':
            return jsonify({'Messsage':
                            'Last name is empty'}), HTTP_400_BAD_REQUEST

        if Email == '':
            return jsonify({'Messsage':
                            'Email is is empty'}), HTTP_400_BAD_REQUEST

        if not validators.email(Email):
            return jsonify({'Messsage':
                            'Email is not valid'}), HTTP_400_BAD_REQUEST
        if Phone == '':
            return jsonify({'Messsage':
                            'phone is is empty'}), HTTP_400_BAD_REQUEST

        if " " in Phone:
            return jsonify({
                'Messsage':
                'Ensure no space inbetween phone number'
            }), HTTP_400_BAD_REQUEST
        if not re.match("[0-9]", Phone):
            return jsonify({
                'Messsage':
                'phone number should not contain letters'
            }), HTTP_400_BAD_REQUEST
        if len(Phone) < 10:
            return jsonify({
                'Messsage':
                'phone number should be atleast 10 characters long'
            }), HTTP_400_BAD_REQUEST
        if len(Phone) > 11:
            return jsonify({
                'Messsage':
                'phone number should not be more than 11 characters long'
            }), HTTP_400_BAD_REQUEST

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

        fullname = fname + " " + lname
        if not isinstance(day, int):
            return jsonify({'Messsage':
                            'day is not a number'}), HTTP_400_BAD_REQUEST
        if not isinstance(month, int):
            return jsonify({'Messsage':
                            'month is not a number'}), HTTP_400_BAD_REQUEST
        if not isinstance(year, int):
            return jsonify({'Messsage':
                            'year is not a number'}), HTTP_400_BAD_REQUEST
        dob = date(year, month, day)
        if Contact.query.filter_by(Email=Email,
                                    User_id=current_user).first():
            return jsonify({'error':
                            'email already exists'}), HTTP_409_CONFLICT
        if Contact.query.filter_by(Phone=Phone,
                                    User_id=current_user).first():
            return jsonify({'error':
                            'Phone already exists'}), HTTP_409_CONFLICT
        if Contact.query.filter_by(Full_name=fullname,
                                    User_id=current_user).first():
            return jsonify({'error':
                            'fullname already exists'}), HTTP_409_CONFLICT
        Contact(Full_name=fullname,
                Email=Email,
                Phone=Phone,
                Birthday=dob,
                User_id=current_user)

        contact.Full_name = fullname
        contact.Email = Email
        contact.Phone = Phone
        contact.Birthday = dob
        contact.User_id = current_user
        db.session.commit()

        return jsonify({
            'Message': 'Updated Successfully',
            'id': contact.id,
            'Email': contact.Email,
            'Phone': contact.Phone,
            'Birthday': contact.Birthday,
            'Userid': contact.User_id,
            'created_at': contact.Create_at,
            'updated_at': contact.Updateed_at,
        }), HTTP_200_OK
    except KeyError as e:
        return jsonify({'Error':
                        str(e) + ' is the problem'}), HTTP_400_BAD_REQUEST
    except Exception as er:
        return jsonify({'Messsage': 'Something went wrong' + str(er)
                        }), HTTP_500_INTERNAL_SERVER_ERROR



# Auth Delete authorized contact user saved 

@contact.delete("/<int:id>")
@jwt_required()
@swag_from("./docs/contact/delete_contact.yaml")
def delete_contact(id):
    current_user = get_jwt_identity()
    contact = Contact.query.filter_by(User_id=current_user, id=id).first()
    if not contact:
        return jsonify({'Message': 'Contact not found'}), HTTP_404_NOT_FOUND
    db.session.delete(contact)
    db.session.commit()
    return jsonify({}), HTTP_204_NO_CONTENT



# @contact.get('/result')
# def result():
#    searchword = request.args.get('q')
#    searchresults = Contact.query.msearch(searchword, fields=['Full_name', 'Email','Phone'], limit =100 )
#    return jsonify({'Message': searchresults}), HTTP_200_OK