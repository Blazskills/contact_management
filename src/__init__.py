from src.constants.http_status_codes import HTTP_200_OK
from flask import Flask, jsonify,request
import os
from src.auth import auth
from src.contact import contact
from src.database import Contact, TokenBlocklist, db
from flask_jwt_extended import JWTManager
from flasgger import Swagger, swag_from
from src.config.swagger import template, swagger_config
from flask_msearch import Search


  
  
  
def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    if test_config is None:
        app.config.from_mapping(
            SECRET_KEY=os.environ.get("SECRET_KEY"),
            SQLALCHEMY_DATABASE_URI=os.environ.get("SQLALCHEMY_DB_URI"),
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            JWT_SECRET_KEY=os.environ.get('JWT_SECRET_KEY'),


            SWAGGER={
                'title': "Contact API",
                'uiversion': 3
            }
        )
    else:
        app.config.from_mapping(test_config)

    db.app = app
    db.init_app(app)
    search = Search()
    search.init_app(app)

    JWTManager(app)
    app.register_blueprint(auth)
    app.register_blueprint(contact)
    jwt = JWTManager(app)
    Swagger(app, config=swagger_config, template=template)


    @app.route('/search')
    def search():
        keyword = request.args.get('q')
        posts = Contact.query.msearch(keyword,fields=['Email''Phone'])(limit=6)
        print(posts)
        data = []
        for post in posts:
            data.append({
                'name':post.User_id,
                'id': post.id
            })
            print(post.User_id)
            return ({'msg':data})

        # return ({'msg'})

    # @app.errorhandler(HTTP_404_NOT_FOUND)
    # def handle_404(e):
    #     return jsonify({'error': 'Not found'}), HTTP_404_NOT_FOUND

    # @app.errorhandler(HTTP_500_INTERNAL_SERVER_ERROR)
    # def handle_500(e):
    #     return jsonify({'error': 'Something went wrong, we are working on it'}), HTTP_500_INTERNAL_SERVER_ERROR

    # Callback function to check if a JWT exists in the database blocklist
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()
        return token is not None
    return app

