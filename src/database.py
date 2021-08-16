from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import secrets
from flask import Flask
# from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
app = Flask(__name__, instance_relative_config=True)
# Init db

db = SQLAlchemy()



# User model


class User(db.Model):
    __tablename__ = "User"
    id = db.Column(db.Integer, primary_key=True)
    Full_name = db.Column(db.String(50), nullable=False)
    User_name = db.Column(db.String(50), unique=True,nullable=False)
    Email = db.Column(db.String(200),unique=True, nullable=False)
    phone = db.Column(db.Integer, unique=True,  nullable=False)
    Userid = db.Column(db.String(50), unique=True, nullable=False)
    Password = db.Column(db.Text(), nullable=False)
    create_at = db.Column(db.DateTime, default=datetime.now())
    updateed_at = db.Column(db.DateTime, onupdate=datetime.now())
    contacts = db.relationship('Contact', backref='user')
    search_histories = db.relationship('Search_History', backref='user')
    email_histories = db.relationship('Email_History', backref='user')

    # def get_token(self,expires_sec=300):
    #     serial= itsSerializer(app.config['SECRET_KEY'], expires_in=expires_sec)
    #     return serial.dumps({'userid':self.Userid}).decode('utf-8')
   
   
    # @staticmethod
    # def verify_token(token):
    #     serial=itsSerializer(app.config['SECRET_KEY'])
    #     try:
    #         userid= serial.loads(token['Userid'])
    #     except:
    #         return None
    #     return User.query.get(userid)


        # userid generator here
    def generate_userid(self):
        generated_user_userid = secrets.token_hex(5)
        check_user_userid = self.query.filter_by(
            Userid=generated_user_userid).first()
        if check_user_userid:
            self.generate_userid()
        else:
            return generated_user_userid

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.Userid = self.generate_userid()

    def __repr__(self) -> str:
        return 'User>>> {self.username}'



# Contact model

class Contact(db.Model):
    __tablename__ = "Contact"
    __searchable__ = ['Full_name', 'Email']
    id = db.Column(db.Integer, primary_key=True)
    Full_name = db.Column(db.String(50), nullable=False)
    Email = db.Column(db.String(100), nullable=False)
    Phone = db.Column(db.Integer,  nullable=False)
    Birthday = db.Column(db.Integer, nullable=False)
    User_id = db.Column(db.String(50), db.ForeignKey('User.Userid'))
    Create_at = db.Column(db.DateTime, default=datetime.now())
    Updateed_at = db.Column(db.DateTime, onupdate=datetime.now())

    def __repr__(self) -> str:
        return '<Contact %r>' % self.Full_name


# Search History model
class Search_History(db.Model):
    __tablename__ = "Search_History"
    id = db.Column(db.Integer, primary_key=True)
    Searched_word = db.Column(db.String(500), nullable=False)
    Searched_by = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.String(50), db.ForeignKey('User.Userid'))
    Time_searched = db.Column(db.DateTime, default=datetime.now())
    updateed_at = db.Column(db.DateTime, onupdate=datetime.now())

    def __repr__(self) -> str:
        return 'Search_History>>> {self.Searched_word}'





class TokenBlocklist(db.Model):
    __tablename__ = "TokenBlocklist"
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)

# Email History model
class Email_History(db.Model):
    __tablename__ = "Email_History"
    id = db.Column(db.Integer, primary_key=True)
    Email_content = db.Column(db.String(500), nullable=False)
    Sent_from = db.Column(db.String(100), nullable=False)
    Sent_to = db.Column(db.String(100), nullable=False)
    Sender_details = db.Column(db.String(500), nullable=False)
    Receiver_details = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.String(50), db.ForeignKey('User.Userid'))
    Date_sent = db.Column(db.DateTime, default=datetime.now())
    updateed_at = db.Column(db.DateTime, onupdate=datetime.now())

    def __repr__(self) -> str:
        return 'Email_History>>> {self.Email_content}'