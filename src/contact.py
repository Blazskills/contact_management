from os import access
from flask import Blueprint, json, request, jsonify, Response
from werkzeug.security import generate_password_hash, check_password_hash
from src.constants.http_status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_409_CONFLICT
import validators
# from src.database import Register,db
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity

contact = Blueprint('contact', __name__, url_prefix='/api/v1/contact')


@contact.get('/me')
def me():
    return 'user seen'



@contact.post('/register')
def register():
    return 'user created'



