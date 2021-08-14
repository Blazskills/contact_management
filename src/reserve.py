    # schema:
    #   type: object
    #   required:
    #     - "First Name"
    #     - "Last Name"
    #     - "Email"
    #     - "phone"
    #     - "day"
    #     - "month"
    #     - "year"
    #   properties:
    #     fname:
    #       type: "First Name"
    #       example: "temitope"
    #     lname:
    #       type: "Last Name"
    #       example: "ilesanmi"
    #     Email:
    #       type: "Email"
    #       example: "ilesanmi@gmail.com"
    #     phone:
    #       type: "phone"
    #       example: "08031100078"
    #     day:
    #       type: "Day"
    #       example: "2"
    #     month:
    #       type: "Month"
    #       example: "12"
    #     year:
    #       type: "year"
    #       example: "1992"
# responses:
#   201:
#     description: New contact Created

#   400:
#     description: Bad request
  
#   409:
#     description: INTERNAL SERVER ERROR

#   500:
#     description: There's a Conflict of data
  




























































# # def mailclient(Email, fullname):
# #     token = s.dumps(Email, salt='email-confirm')
# #     msg = Message('Password Reset Request', sender='info@toismart.com', recipients=[str(Email)])
# #     link = url_for('confirm_token', token=token, _external=True)
# #     msg.body = 'You requested for a password reset {}'.format(fullname)+'Your password reset link is {}'.format(link)
# #     msg.html = '<p>ou requested for a password reset {}. </p>'.format(fullname)+'</br><p>Your password reset link is {}.</p>'.format(link)
# #     # msg.html = render_template('text.html')
# #     mail.send(msg)


# # @auth.post('/reset_password')
# # def reset_password():
# #     try:
# #         if request.content_type != 'application/json':
# #             return jsonify({
# #                 'Messsage':
# #                 'Bad request, Content-type must be json type'
# #             }), HTTP_400_BAD_REQUEST
# #         request_data = request.get_json()
# #         if not request_data:
# #             return jsonify({"Messsage": "Empty request"}), HTTP_400_BAD_REQUEST
# #         Email = request_data['Email']
# #         if not validators.email(Email):
# #             return jsonify({'Messsage':
# #                             'Email is not valid'}), HTTP_400_BAD_REQUEST
# #         user = User.query.filter_by(Email=Email).first()
# #         if not user:
# #             return {"Message": "email is invalid"}, HTTP_401_UNAUTHORIZED
# #         fullname=user.Full_name
# #         mailclient(Email,fullname)
# #     except KeyError as e:
# #         return jsonify({'Error': str(e) + ' is missing'}), HTTP_400_BAD_REQUEST


# # @auth.post('/confirm_token/<token>')
# # def confirm_token(token):
# #     try:
# #         Email = s.loads(token, salt='email-confirm', max_age=3600)
# #         user = User.query.filter_by(Email=Email).first()
# #         if user:
# #             return jsonify({'Message': 'The token works! Password seen',
# #             'user':user.Full_name
# #             }), HTTP_401_UNAUTHORIZED

# #             # request_data = request.get_json()
# #             # Password = request_data['Password']
# #     except SignatureExpired:
# #             return jsonify({'msg': 'token expired'})
    
