import os
from flask import Blueprint, request, jsonify, render_template, session, abort, redirect
from bson import json_util, objectid
from functools import wraps
from bson import objectid
from datetime import timedelta
import jwt
from settings import SALT
from utils.util import getID, generateOTP, getFormImages, saveImage, create_report_task
SECRET_KEY = SALT
import datetime
from random import randint
from bson import ObjectId
from utils.util import encrypt
import pathlib
import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from decouple import config

def common_bp(mongo, mail):
    common = Blueprint('common', __name__)

    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  #this is to set our environment to https because OAuth 2.0 only supports https environments

    GOOGLE_CLIENT_ID = config("GOOGLE_CLIENT_ID")  #enter your client id you got from Google console
    client_secrets_file = os.path.join(pathlib.Path(__file__).parent, config("GOOGLE_CLIENT_ID_LOCATION"))  #set the path to where the .json file you got Google console is

    flow = Flow.from_client_secrets_file(  #Flow is OAuth 2.0 a class that stores all the information on how we want to authorize our users
        client_secrets_file=client_secrets_file,
        scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],  #here we are specifing what do we get after the authorization
        redirect_uri="https://stage-api.billionviews.ai/callback"  #and the redirect URI is the point where the user will end up after the authorization
    )

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
    


    @common.route("/social-login")  #the page where the user can login
    def login():
        req_param = request.args
        authorization_url, state = flow.authorization_url()  #asking the flow class for the authorization (login) url
        session["state"] = state
        session["type"] = req_param.get("type","")
        session["redirect_uri"] = req_param.get("redirect_uri", "https://billion-views-nextjs.vercel.app/")
        print(session["type"])
        # return jsonify({'redirect_link':authorization_url }), 200
        return redirect(authorization_url)


    @common.route("/callback")  #this is the page that will handle the callback process meaning process after the authorization
    def callback():
        flow.fetch_token(authorization_response=request.url)
        req_params = request.args

        if not session["state"] == request.args["state"]:
            abort(500)  #state does not match!

        credentials = flow.credentials
        request_session = requests.session()
        cached_session = cachecontrol.CacheControl(request_session)
        token_request = google.auth.transport.requests.Request(session=cached_session)

        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID
        )

        session["google_id"] = id_info.get("sub")  #defing the results to show on the page
        session["name"] = id_info.get("name")
        redirect_uri = session.get("redirect_uri")
        # if "sign-in" in redirect_uri:
        #     redirect_uri_query_params = '?state={}&code={}'.format(req_params['state'],req_params['code'])
        #     redirect_uri = redirect_uri + redirect_uri_query_params

        editors = mongo.db.users
        usr_obj = mongo.db.users
        filter = {'email': id_info['email']}
        e = editors.find_one(filter)
        if e:
            if 'social_user' in e and e['social_user'] is True:
                if e['social_login_id'] == id_info.get("sub"):
                    claims = e
                    if 'first_login' not in e:
                        e['first_login'] = None
                    if e['first_login'] is None:
                        upd_obj = usr_obj.update_one({"_id":e['_id']},{"$set":{"social_code":req_params['code'],"social_state":req_params['state'], "last_login":datetime.datetime.now(), "has_login":True,"first_login":True}})
                    elif e['first_login'] is True:
                        upd_obj = usr_obj.update_one({"_id":e['_id']},{"$set":{"social_code":req_params['code'],"social_state":req_params['state'], "last_login":datetime.datetime.now(), "has_login":True,"first_login":False}})
                    user_type = session["type"]
                    if user_type != "":
                        if e['type'] == "":
                            upd_obj1 = usr_obj.update_one({"_id":e['_id']},{"$set":{"type":user_type}})
                    # claims['id'] = str(claims['_id'])
                    # encoded_id = encrypt(claims['id']) + '-' + encrypt(str(datetime.datetime.now()))
                    
                    # del claims['_id']
                    # del claims['password']
                    # claims['expiry'] = str(datetime.datetime.utcnow() + timedelta(days=30))
                    # del e['expiry']
                    # del e["otp"]
                    # del e["email_verified"]
                    # del e ["otp_exp"]
                    # del e["is_active"]
                    
                    # token = jwt.encode(claims, SALT)
                    # response = jsonify({'message': 'Social Login Successfully.', 'data': e, 'token': token})
                    redirect_uri_query_params = '?state={}&code={}'.format(req_params['state'],req_params['code'])
                    redirect_uri = redirect_uri + redirect_uri_query_params
                    return redirect(redirect_uri)
                else:
                    response = jsonify({'message': "Social Login ID does not match"})
                    return response, 401
            else:
                response = jsonify({'message': "This user is register as normal user"})
                return response, 401

        first_last_name = id_info.get("name","Google User").split(" ")
        if len(first_last_name) > 0:
            first_name = first_last_name[0]
        if len(first_last_name) > 1:
            last_name = first_last_name[-1]

        e = {
            'email': id_info.get('email'),
            'firstName': first_name,
            'lastName': last_name,
            'password': "",
            'type': session["type"],
            "social_user":True,
            "social_login_id":id_info.get("sub"),
            'contacts':{},
            'first_login':None,
        }

        
        e['otp'] = 000000
        e['is_active'] = True
        e['email_verified'] = True
        e["otp_exp"] = datetime.datetime.utcnow() + timedelta(minutes=59)
        e_id = str(editors.insert_one(e).inserted_id)
        upd_obj = usr_obj.update_one({"_id":ObjectId(e_id)},{"$set":{"social_code":req_params['code'],"social_state":req_params['state']}})
        # e['id'] = str(e_id)
        # encoded_id = encrypt(e['id']) + '-' + encrypt(str(datetime.datetime.now()))
        # del e['_id']
        # del e['password']
        # claims = e
        # claims['expiry'] = str(datetime.datetime.utcnow() + timedelta(days=30))
        # del claims["otp_exp"]
        # token = jwt.encode(claims, SALT)
        # del e["expiry"]
        # del e["otp"]
        # del e["email_verified"]
        # del e["is_active"]
        # token = jwt.encode(claims, SALT)
        # response = jsonify({'data': e, 'message': "Social Signup Successful!", "token":token})
        session.clear()
        return redirect(redirect_uri)
        # return redirect("/protected_area")  #the final page where the authorized users will end up

    @common.route("/social/fetch-token", methods=['POST'])  #this is the page that will handle the callback process meaning process after the authorization
    def fetch_token():
        usr_obj = mongo.db.users
        req_body = request.get_json()
        filter = {'social_code':req_body["code"], "social_state":req_body["state"]}
        e = usr_obj.find_one(filter)
        if e:
            if 'social_user' in e and e['social_user'] is True:
                    e['has_login'] = e.get('has_login',False)
                    claims = e
                    upd_obj = usr_obj.update_one({"_id":e['_id']},{"$set":{"social_code":"","social_state":""}})
                    claims['id'] = str(claims['_id'])
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
                    response = jsonify({'message': 'Social Login Successfully.', 'data': e, 'token': token})
                    return response, 200
            else:
                response = jsonify({'message': "This user is register as normal user"})
                return response, 401
        else:
            return jsonify({'message': 'User not found!'}), 400


    @common.route("/logout")  #the logout page and function
    def logout():
        session.clear()
        response = jsonify({'message': "Logout Successful!"})
        return response, 201

    @common.route('/user/update-name', methods=['PUT'])
    @token_required
    def UpadateName():
        print("-----------------------")
        token = request.headers.get('Authorization')
        req_body = request.get_json()        
        cre_obj = mongo.db.users

        if token:
            user_obj = getID(token)
            print(user_obj)

        else:
            response = jsonify({'data': None, 'message': "Invalid Token"})
            return response, 401
        
        cre_obj.update_one({"_id":ObjectId(user_obj["id"])},{"$set":req_body})
        common_obj = cre_obj.find_one({"_id":ObjectId(user_obj["id"])})
        if not common_obj:
            data_obj = {"message":"Incorrect User Id."}
            return data_obj

        data ={
            "email" : common_obj["email"],
            "firstName" : common_obj["firstName"],
            "lastName" : common_obj["lastName"]
        }
        response = jsonify({'data': data, "message":"Profile Updated Successfully."})
        return response, 201
    
    @common.route('/user/update-email', methods=['PUT'])
    @token_required
    def UpdateEmail():
        print("-----------------------")
        token = request.headers.get('Authorization')
        req_body = request.get_json()        
        cre_obj = mongo.db.users

        if token:
            user_obj = getID(token)

        else:
            response = jsonify({'data': None, 'message': "Invalid Token"})
            return response, 401

        common = cre_obj.find_one({"email":req_body["email"]})

        if common is not None :
            response = jsonify({'data': None, 'message': "Email already exist."})
            return response, 400
        else:
            req_body['email_verified'] = False
            otp = randint(111111,999999)
            req_body['otp'] = otp
            req_body["otp_exp"] = datetime.datetime.utcnow() + timedelta(minutes=59)
            req_body['expiry'] = str(datetime.datetime.utcnow() + timedelta(days=30))
            cre_obj.update_one({"_id":ObjectId(user_obj["id"])},{"$set":req_body})
            
            email_status = generateOTP(mail, req_body['email'], otp)
            
            if email_status is True:
                response = jsonify({'data': None, 'message': "User Registed and OTP sent for verification!"})
            else:
                response = jsonify({'data': None, 'message': "User Registed and OTP not sent for verification!"})
            return response, 201
        

    @common.route('/user/update-portfolio', methods=['PUT'])
    @token_required
    def UpdatePortfolio():
        token = request.headers.get('Authorization')
        req_body = request.get_json()        
        cre_obj = mongo.db.users

        if token:
            user_obj = getID(token)
            # print(user_obj)
        else:
            response = jsonify({'data': None, 'message': "Invalid Token"})
            return response, 401
        cre_obj.update_one({"_id":ObjectId(user_obj["id"])},{"$set":req_body})
        common_obj = cre_obj.find_one({"_id":ObjectId(user_obj["id"])})

        if not common_obj:
            data_obj = {"message":"Incorrect User Id."}
            return data_obj

        data ={
            "portfolio" : common_obj["portfolio"]
            
        }
        response = jsonify({'data': data, "message":"Portfolio Updated Successfully."})
        return response, 201
    

    @common.route('/user/profile-picture', methods=['PUT'])
    @token_required
    def profilePictrue():
        token = request.headers.get('Authorization')
        req_body ={}
        req_body['profile_picture'] = getFormImages(request)
        req_body['profile_picture'] = saveImage(req_body['profile_picture'][0])
        cre_obj = mongo.db.users

        if token:
            user_obj = getID(token)
        else:
            response = jsonify({'data': None, 'message': "Invalid Token"})
            return response, 401
        cre_obj.update_one({"_id":ObjectId(user_obj["id"])},{"$set":req_body})
        common_obj = cre_obj.find_one({"_id":ObjectId(user_obj["id"])})
        if not common_obj:
            data_obj = {"message":"Incorrect User Id."}
            return data_obj
        
        data ={
            "profile_picture" : common_obj["profile_picture"]
            
        }
        response = jsonify({'data': data, "message":"Portfolio Updated Successfully."})
        return response, 201
    
    @common.route('/user/upload', methods=['PUT'])
    # @token_required
    def uploadMedia():
        req_body ={}
        req_body['media'] = getFormImages(request)
        media_link = []
        for n_file in req_body['media']:
            media_link.append(saveImage(n_file))
        
        data = media_link
        response = jsonify({'data': data, "message":"Media Uploaded Successfully."})
        return response, 201
    
    @common.route('/job/report', methods=['POST'])
    # @token_required
    def report_job():
        req_params = request.args
        req_body = request.get_json()
        reports = mongo.db.reports
        if 'job_id' not in req_params:
            return {"message":"Please provide all mandatory fields!"}, 400
        
        try:
            token = request.headers.get('Authorization')
            decoded_token = getID(token)
            dup_obj = reports.count_documents({"job_id":req_params['job_id'],"reporter_id":decoded_token['id']})
            if dup_obj:
                return {"message":"You have already reported on this job!"}, 400
            
            req_body['report_type'] = "job"
            req_body['reporter_id'] = decoded_token['id']
            req_body['job_id'] = req_params['job_id']
            req_body['reporter_type'] = decoded_token['type']

            
            reports.insert_one(req_body)
            create_report_task(req_body)
            return {"message":"Reported Successfully."}, 201
        except Exception as e:
            print(str(e))
            return {"message":"Something went wrong!"}, 201
    
    return common