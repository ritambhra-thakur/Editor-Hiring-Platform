from flask import Blueprint, request, jsonify
from bson import json_util, objectid
from functools import wraps
from bson import objectid
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import datetime
import jwt
from .schema import LoginSchema, RegisterSchema
from settings import SALT
SECRET_KEY = SALT
from emails import send
from random import randint
from utils.util import getID, generateOTP, generateVerificationLink, encrypt, decrypt


def auth_bp(mongo, mail):

    auth = Blueprint('auth', 'auth', __name__)

    def validate_token(f):
        @wraps(f)
        def decorator(*args, **kwargs):
            token = None

            if 'Authorization' in request.headers:
                token = request.headers['Authorization']

            if not token:
                return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
            
            try:
                token_encoded = str.encode(token)
                # print(token_encoded)
                data = jwt.decode(token_encoded, SALT, algorithms=['HS256'])
                employer = mongo.db.employers.find_one({'_id': objectid.ObjectId(data['id'])})
            except Exception as e:
                print(e)
                return jsonify({'status': 'error', 'message': 'invalid token'})
            
            return f(employer, *args, **kwargs)
        return decorator
    
    def token_required(f):
        @wraps(f)
        def decorated(*argrs, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                return jsonify({'Message': 'Token is missing'})
            try:
                data = jwt.decode(token, SECRET_KEY, algorithms = 'HS256')
            except:
                # return False
                return jsonify({'status':401,'message':'Invalid Token'})
            return f(*argrs, **kwargs)
        return decorated
    

    # @auth.route('/auth/login', methods=['POST'])
    # def handle_login():
    #     login_schema = LoginSchema()
    #     req_body = request.get_json()
    #     errors = login_schema.validate(req_body)
    #     if errors:
    #         response = jsonify({
    #             'status': 'error',
    #             'message': 'Invalid mobile number and/or password'
    #         })

    #         return response, 401
        
    #     employers = mongo.db.employers
    #     filter = {'email': req_body['email']}
    #     e = employers.find_one(filter)
    #     if not e:
    #         response = jsonify({'status': 'error', 'message': 'Invalid email and/or password'})
    #         return response, 401

    #     if check_password_hash(e['password'], req_body['password']):
    #         claims = e
    #         claims['id'] = str(claims['_id'])
    #         del claims['_id']
    #         del claims['password']
    #         claims['expiry'] = str(datetime.datetime.utcnow() + timedelta(days=30))
    #         token = jwt.encode(claims, SALT)
    #         return jsonify({'status': 'success', 'token': token})
        
    # @auth.route('/auth/register', methods=['POST'])
    # def handle_register():
        
    #     schema = RegisterSchema()
    #     req_body = request.get_json()
    #     errors = schema.validate(req_body)
    #     if errors:
    #         print('errors: ', errors)
    #         response = jsonify({
    #             'status': 'error',
    #             'message': 'Could not register merchant.'
    #         })
    #         return response, 401
    #     employers = mongo.db.employers
    #     filter = {'email': req_body['email']}
    #     e = employers.find_one(filter)
    #     if e:
    #         response = jsonify({
    #             'data': None,
    #             'message': 'This email is already registered.'
    #         })
    #         return response, 401
    #     print('HERE 3')
    #     pass_hash = generate_password_hash(req_body['password'])
    #     e = {
    #         'email': req_body['email'],
    #         'password': pass_hash,
    #         'status': 'active',
    #         'role': 'employer',
    #         'verified': False
    #     }
    #     e_id = str(employers.insert_one(e).inserted_id)
    #     e['id'] = str(e_id)
    #     del e['_id']
    #     del e['password']
    #     claims = e
    #     claims['expiry'] = str(datetime.datetime.utcnow() + timedelta(days=30))
    #     token = jwt.encode(claims, SALT)
    #     response = jsonify({'data': e, 'token': token})
    #     send([e['email']])
    #     return response, 201

    @auth.route('/auth/login', methods=['POST'])
    def handle_login():
        login_schema = LoginSchema()
        req_body = request.get_json()
        errors = login_schema.validate(req_body)
        if errors:
            response = jsonify({
                'status': 'error',
                'message': 'Invalid mobile number and/or password'
            })
   
            return response, 401
        
        editors = mongo.db.users
        
        filter = {'email': req_body['email']}
        e = editors.find_one(filter)
        
        if not e:
            response = jsonify({'data': None, 'message': 'Invalid email and password.'})
            return response, 401
        
        else:
            is_active = e.get("is_active")
            email_verified = e.get("email_verified")
            chk = check_password_hash(e['password'], req_body['password'])
            
            if chk is True:
                if email_verified is not True:
                    response = jsonify({'data': None, 'message': 'Email not verified'})
                    return response, 401
                
                if is_active is not True:
                    response = jsonify({'data': None, 'message': 'User is In-active'})
                    return response, 401
                
                claims = e
                claims['id'] = str(claims['_id'])
                o_id = claims['_id']
                del claims['_id']
                del claims['password']
                claims['expiry'] = str(datetime.datetime.utcnow() + timedelta(days=30))
                del e['expiry']
                del e["otp"]
                del e["email_verified"]
                del e ["otp_exp"]
                del e["is_active"]
                if 'last_login' in e:
                    del e["last_login"]
                token = jwt.encode(claims, SALT)

                # updating last_login details
                if 'first_login' not in e:
                    e['first_login'] = None

                if e['first_login'] is None:
                    editors.update_one({"_id":o_id},{"$set":{"last_login":datetime.datetime.now(), "has_login":True, "first_login":True}})
                    e["first_login"] = True
                elif e['first_login'] is True:
                    editors.update_one({"_id":o_id},{"$set":{"last_login":datetime.datetime.now(), "has_login":True, "first_login":False}})
                    e["first_login"] = False
                e["has_login"] = True
                response = jsonify({'message': 'Login Successfully.', 'data': e, 'token': token})
                return response, 200
            else :
                response = jsonify({'data': None, 'message': 'Incorrect Password.'})
                return response, 401

        
    @auth.route('/auth/register', methods=['POST'])
    def handle_register():
        # schema = RegisterSchema()
        req_body = request.get_json()
        editors = mongo.db.users
        filter = {'email': req_body['email']}
        e = editors.find_one(filter)
        if e:
            response = jsonify({
                'data': None,
                'message': 'This email is already registered.'
            })
            return response, 401

        
        pass_hash = generate_password_hash(req_body['password'])
        # if req_body["type"] != "editor":
        #     data={"message" : "Type must be Editor."}
        #     return data
        # else:
        e = {
            'email': req_body['email'],
            'firstName': req_body['firstName'],
            'lastName': req_body['lastName'],
            'password': pass_hash,
            'type': req_body["type"],
            'contacts':{},
            'first_login':None
        }

        
        otp = randint(111111,999999)
        e['otp'] = otp
        e['is_active'] = False
        e['email_verified'] = False
        email_status = generateOTP(mail, req_body['email'], otp)
        e["otp_exp"] = datetime.datetime.utcnow() + timedelta(minutes=59)
        e_id = str(editors.insert_one(e).inserted_id)
        e['id'] = str(e_id)
        del e['_id']
        del e['password']
        claims = e
        claims['expiry'] = str(datetime.datetime.utcnow() + timedelta(days=30))
        del claims["otp_exp"]
        token = jwt.encode(claims, SALT)
        del e["expiry"]
        del e["otp"]
        del e["email_verified"]
        del e["is_active"]
        
        if email_status is True:
            response = jsonify({'data': e, 'message': "User Registed and OTP sent for verification!"})
        else:
            response = jsonify({'data': e, 'message': "User Registed and OTP not sent for verification!"})
        return response, 201


    @auth.route('/auth/verify-email', methods=['POST'])
    def VerifyEmail():
        req_body = request.get_json()
        editors = mongo.db.users
        editor_obj = editors.find_one({"email":req_body['email']})
        if not editor_obj:
            response = jsonify({'data': None, "message":"Incorrect Email."})
            return response, 400
        if  editor_obj['otp'] == req_body['otp']:
            if datetime.datetime.utcnow() <= editor_obj['otp_exp']:
                data_to_insert = {"otp":None, "is_active":True, "email_verified":True}
                editors.update_one({"email":req_body['email']},{"$set":data_to_insert})
                response = jsonify({'data': None, "message":"OTP verified successfully!"})
                return response, 200    
            else:
                response = jsonify({'data': None, "message":"OTP is expired."})
            return response, 400        
        else:
            response = jsonify({'data': None, "message":"Incorrect OTP."})
            return response, 400    
        

    @auth.route('/auth/update-profile', methods=['PUT'])
    @token_required
    def UpdateProfile():
        req_body = request.get_json()
        editors = mongo.db.users
        
        editors.update_one({"email":req_body['email']},{"$set":req_body})
        editor_obj = editors.find_one({"email":req_body['email']})
        if not editor_obj:
            data_obj = {"message":"Incorrect Email."}
            return data_obj
        del editor_obj['_id']
        del editor_obj["otp"]
        del editor_obj["email_verified"]
        del editor_obj["is_active"]
        response = jsonify({'data': editor_obj, 'message': "Profile Updated Successfully."})
        return response, 201

    
    @auth.route('/auth/change-password', methods=['PUT'])
    @token_required
    def change_password():
        token = request.headers.get('Authorization')
        
        get_obj= getID(token)
        req_body = request.get_json()
        editors = mongo.db.users
        editor_obj = editors.find_one({"email":get_obj['email']})
        if not editor_obj:
            data_obj = {"message":"Incorrect Email."}
            return data_obj
        
        chk = check_password_hash(editor_obj['password'], req_body['currentPassword'])
        if chk is True:
            pass_hash = generate_password_hash(req_body['newPassword'])
            req_body['password'] = pass_hash
            del req_body['currentPassword']
            del req_body['newPassword']
            editors.update_one({"email":get_obj['email']},{"$set":req_body})
            
            del editor_obj['_id']
            del editor_obj['password']
            del editor_obj["otp"]
            del editor_obj["email_verified"]
            del editor_obj["is_active"]
            response = jsonify({'data': editor_obj, 'message': "Password Changed Succesfully."})
            return response, 201
        else :
            response = jsonify({'data': None, 'message': 'Incorrect  Old Password.'})
            return response, 401
        
    
    @auth.route('/auth/forget-password-link', methods=['POST'])
    def GetForgotPasswordLink():
        req_body = request.get_json()
        edit_obj = mongo.db.users
        message=req_body["email"]
        editor_obj = edit_obj.find_one({"email":message})
        if not editor_obj:
            data_obj = {'data': None,"message":"Email does not exist.."}
            return data_obj, 401
        enc_mail= encrypt(message)
        editor_obj = {}
        editor_obj["verified_link"] = True
        edit_obj.update_one({"email":message}, {"$set":editor_obj})
        verification_link="http://localhost:3000/account/change-password/{}".format(enc_mail)
        email_status = generateVerificationLink(mail, req_body['email'], verification_link)
        if email_status is True:
            response = jsonify({'data': None, 'message': "Forget Password Link Sent to your Email."})
        else:
            response = jsonify({'data': None, 'message': "Forget Password Link Not Sent to your Email."})
        return response, 201
    
    @auth.route('/auth/forget-password', methods=['POST'])
    def ForgotPassword():
        req_body = request.get_json()
        enc_mail=req_body["resetToken"]
        email= decrypt(enc_mail)
        editor = mongo.db.users
        editor_obj = editor.find_one({"email":email})
        if editor_obj["verified_link"] is True:
            password_hash = generate_password_hash(str(req_body['newPassword']))
            editor.update_one({"email":email},{"$set":{"password":password_hash,"verified_link":False}})
            response = jsonify({'data': None, 'message': "Forget Password Successfully."})
            return response, 200
        else:
            response = jsonify({'data': None, 'message': 'Link Expired!'})
            return response, 400

    
    return auth