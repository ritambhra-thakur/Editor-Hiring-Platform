from flask import Blueprint, request, jsonify
from bson import json_util, objectid
from functools import wraps
from bson import objectid
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import jwt
from .schema import LoginSchema, RegisterSchema
# from db import mongo
from settings import SALT
from utils.util import getID, generateOTP, generateVerificationLink, encrypt, decrypt, get_paginated_list
SECRET_KEY = SALT
import datetime
from random import randint
from bson import ObjectId
from dateutil import parser
from utils.util import humanize_date, calc_application_completion, create_clickup_task, create_report_task

def reviewers_bp(mongo, mail):
    reviewers = Blueprint('reviewers', __name__)

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
                data = jwt.decode(token_encoded, SALT, algorithms=['HS256'])
                rev = mongo.db.reviewers.find_one({'_id': objectid.ObjectId(data['id'])})
            except Exception as e:
                print(e)
                return jsonify({'status': 'error', 'message': 'invalid token'})
            
            return f(rev, *args, **kwargs)
        return decorator

    @reviewers.route('/creator/login', methods=['POST'])
    def handle_login():
        login_schema = LoginSchema()
        req_body = request.get_json()
        errors = login_schema.validate(req_body)
        if errors:
            response = jsonify({
                'status': None,
                'message': 'Invalid mobile number and/or password'
            })

            return response, 401

        print(req_body)
        
        reviewers = mongo.db.creator
        filter = {'email': req_body['email']}
        rev = reviewers.find_one(filter)
        is_active = rev.get("is_active")
        email_verified = rev.get("email_verified")
        if not rev:
            response = jsonify({'data': None, 'message': 'Invalid email and password.'})
            return response, 401

        else:
            chk = check_password_hash(rev['password'], req_body['password'])
            if chk is True:
                if email_verified is not True:
                    response = jsonify({'data': None, 'message': 'Email not verified'})
                    return response, 401
                
                if is_active is not True:
                    response = jsonify({'data': None, 'message': 'User is In-active'})
                    return response, 401
                
                claims = rev
                claims['id'] = str(claims['_id'])
                del claims['_id']
                del claims['password']
                claims['expiry'] = str(datetime.datetime.utcnow() + timedelta(days=30))
                del rev ['expiry']
                del rev ["otp_exp"]
                del rev["otp"]
                del rev["email_verified"]
                del rev["is_active"]
                token = jwt.encode(claims, SALT)
                response = jsonify({'message': 'Login Successfully.', 'data': rev,'token': token})
                return response, 200
            else :
                response = jsonify({'data': None, 'message': 'Incorrect Password.'})
                return response, 401
            
    @reviewers.route('/creator/register', methods=['POST'])
    def handle_register():
        schema = RegisterSchema()
        req_body = request.get_json()
        errors = schema.validate(req_body)
        if errors:
            print('errors: ', errors)
            response = jsonify({
                'status': 'error',
                'message': 'Could not register merchant.'
            })
            return response, 401
        reviewers = mongo.db.creator
        filter = {'email': req_body['email']}
        rev = reviewers.find_one(filter)
        if rev:
            response = jsonify({
                'data': None,
                'message': 'This email is already registered.'
            })
            return response, 401
        
        pass_hash = generate_password_hash(req_body['password'])
        if req_body["type"] != "creator":
            data={"message" : "Type must be Creator."}
            return data
        else:
            rev = {
                'email': req_body['email'],
                'firstName': req_body['firstName'],
                'lastName': req_body['lastName'],
                'password': pass_hash,
                'type': req_body['type'],
                'contacts':{}

            }
        otp = randint(111111,999999)
        rev['otp'] = otp
        rev['is_active'] = False
        rev['email_verified'] = False
        email_status = generateOTP(mail, req_body['email'], otp)
        rev["otp_exp"] = datetime.datetime.utcnow() + timedelta(minutes=59)
        rev_id = str(reviewers.insert_one(rev).inserted_id)
        rev['id'] = str(rev_id)
        del rev['_id']
        del rev['password']
        claims = rev
        claims['expiry'] = str(datetime.datetime.utcnow() + timedelta(days=30))
        del claims["otp_exp"]
        token = jwt.encode(claims, SALT)
        del rev["expiry"]
        del rev["otp"]
        del rev["email_verified"]
        del rev["is_active"]

        if email_status is True:
            response = jsonify({'data': rev, 'message': "User Registed and OTP sent for verification!"})
        else:
            response = jsonify({'data': rev, 'message': "User Registed and OTP not sent for verification!"})
        return response, 201


    @reviewers.route('/creator/verify-email', methods=['POST'])
    def VerifyEmail():
        req_body = request.get_json()
        creators = mongo.db.creator
        cre_obj = creators.find_one({"email":req_body['email']})
        if not cre_obj:
            data_obj = {"message":"Incorrect Email."}
            return data_obj
        if  cre_obj['otp'] == req_body['otp']:
            if datetime.datetime.utcnow() <= cre_obj['otp_exp']:
                data_to_insert = {"otp":None, "is_active":True, "email_verified":True}
                creators.update_one({"email":req_body['email']},{"$set":data_to_insert})
                response = jsonify({'data': None, "message":"OTP verified successfully!"})
                return response, 200    
            else:
                response = jsonify({'data': None, "message":"OTP is Expired."})
                return response, 400 
        else:
            response = jsonify({'data': None, "message":"Incorrect OTP."})
            return response, 400
    

    @reviewers.route('/creator/update-profile', methods=['PUT'])
    @token_required
    def UpdateProfile():
        req_body = request.get_json()
        cre_obj = mongo.db.creator
        
        cre_obj.update_one({"email":req_body['email']},{"$set":req_body})
        creator_obj = cre_obj.find_one({"email":req_body['email']})
        if not creator_obj:
            data_obj = {"message":"Incorrect Email."}
            return data_obj
        del creator_obj['_id']
        del creator_obj["otp"]
        del creator_obj["email_verified"]
        del creator_obj["is_active"]
        response = jsonify({'data': creator_obj, "message":"Profile Updated Successfully."})
        return response, 201

    @reviewers.route('/creator/change-password', methods=['PUT'])
    @token_required
    def change_password():
        token = request.headers.get('Authorization')
        
        get_obj= getID(token)
        req_body = request.get_json()
        creat_obj = mongo.db.creator
        creator_obj = creat_obj.find_one({"email":get_obj['email']})
        if not creator_obj:
            data_obj = {"message":"Incorrect Email."}
            return data_obj
        
        chk = check_password_hash(creator_obj['password'], req_body['currentPassword'])
        if chk is True:
            pass_hash = generate_password_hash(req_body['newPassword'])
            req_body['password'] = pass_hash
            del req_body['currentPassword']
            del req_body['newPassword']
            creat_obj.update_one({"email":get_obj['email']},{"$set":req_body})
            
            del creator_obj['_id']
            del creator_obj['password']
            del creator_obj["otp"]
            del creator_obj["email_verified"]
            del creator_obj["is_active"]
            response = jsonify({'data': creator_obj, 'message': "Password Changed Succesfully."})
            return response, 201
        else :
            response = jsonify({'data': None, 'message': 'Incorrect  Old Password.'})
            return response, 401
        

    @reviewers.route('/creator/forget-password-link', methods=['POST'])
    def GetForgotPasswordLink():
        req_body = request.get_json()
        creat_obj = mongo.db.creator
        message=req_body["email"]
        enc_mail= encrypt(message)
        creator_obj = {}
        creator_obj["verified_link"] = True
        creat_obj.update_one({"email":message}, {"$set":creator_obj})
        verification_link="google.com?={}".format(enc_mail)
        email_status = generateVerificationLink(mail, req_body['email'], verification_link)
        if email_status is True:
            response = jsonify({'data': None, 'message': "Forget Password Link Sent to your Email."})
        else:
            response = jsonify({'data': None, 'message': "Forget Password Link Not Sent to your Email."})
        return response, 201
    

    @reviewers.route('/creator/forget-password', methods=['POST'])
    def ForgotPassword():
        req_body = request.get_json()
        enc_mail=req_body["resetToken"]
        email= decrypt(enc_mail)
        creator = mongo.db.creator
        creator_obj = creator.find_one({"email":email})
        if creator_obj["verified_link"] is True:
            password_hash = generate_password_hash(str(req_body['newPassword']))
            creator.update_one({"email":email},{"$set":{"password":password_hash,"verified_link":False}})
            response = jsonify({'data': None, 'message': "Forget Password Successfully."})
            return response, 200
        else:
            response = jsonify({'data': None, 'message': 'Link Expired!'})
            return response, 400


# <-------------------------------------------------Job-Post---------------------------------------------->
  
    @reviewers.route('/creator/job-post/create', methods=['POST'])
    @token_required
    def createjob():
        token = request.headers.get('Authorization')
        if token:
            user_obj = getID(token)
        else:
            response = jsonify({'data': None, 'message': "Invalid Token"})
            return response, 401
        
        
        job_obj = mongo.db.jobs
        req_body = request.get_json()
        req_body['user_id'] = user_obj['id']
        req_body['status'] = 'active'
        doc = job_obj.insert_one(req_body)
        # del req_body["_id"]
        if doc:
            clickup_task_id = create_clickup_task(req_body)
            print(clickup_task_id)
            job_obj.update_one({"_id":req_body['_id']},{"$set":{"clickup_task_id":clickup_task_id}})
            response = jsonify({'data' : str(req_body["_id"]),'message': "Job Posted Successfully."})

            return response, 200
        else:
            response = jsonify({'data': None, 'message': 'Job has not created Successfully.'})
            return response, 400
        
        
    @reviewers.route('/creator/job-post/update/<id>', methods=['PUT'])
    @token_required
    def updatejob(id):
        job_obj = mongo.db.jobs
        req_body = request.get_json()
        print("=====================")
        print(req_body)
        print("=====================")
        doc = job_obj.update_one({"_id":ObjectId(id)},{"$set":req_body})
        updated_record = job_obj.find_one({"_id":ObjectId(id)})
        del updated_record['_id']
        if doc:
            response = jsonify({'data': updated_record, 'message': "Job has been Updated."})
            return response, 200
        else:
            response = jsonify({'data': None, 'message': 'Job not Updated.'})
            return response, 400

    
    @reviewers.route('/creator/job-post/delete/<id>', methods=['DELETE'])
    @token_required
    def delJobByID(id):
        job_obj = mongo.db.jobs
        doc = job_obj.delete_one({"_id":ObjectId(id)})
        if doc:
            response = jsonify({'data': "OK", 'message': "Job has been Deleted."})
            return response, 200
        else:
            response = jsonify({'data': None, 'message': 'Job not Deleted.'})
            return response, 400
    
    @reviewers.route('/creator/job-post/get-by-id/<id>', methods=['GET'])
    @token_required
    def getbyId(id):
        job_obj = mongo.db.jobs
        app_obj=mongo.db.applicants
        get_record = job_obj.find_one({"_id":ObjectId(id)})
        del get_record['_id']
        data={
            "id":id,
            "title" : get_record["title"],
            "category" : get_record["category"],
            "duration" : get_record["duration"],
            "budget" : get_record["budget"],
            "deadline" : get_record["deadline"],
            "createdAt" : get_record["createdAt"],
            "applicantsCount" : app_obj.count_documents({"job_id":id}),
            "projectType" : get_record["projectType"],
            "jobSite" : get_record["jobSite"],
        }
        if get_record:
            response = jsonify({'jobs': data, 'message': "You have got the Job Details."})
            return response, 200
        else:
            response = jsonify({'data': None, 'message': 'You have not got the Job Details.'})
            return response, 400
        
    @reviewers.route('/creator/get-by-token/job-post/', methods=['GET'])
    @token_required
    def getUserJob():
        job_obj = mongo.db.jobs
        token = request.headers.get('Authorization')
        if token:
            
            user_obj = getID(token)
            # print("------------------------>>>>>>>>>>>>>>>>>>>>")
            # print(user_obj["id"])
            # print("------------------------>>>>>>>>>>>>>>>>>>>>")

        else:
            response = jsonify({'data': None, 'message': "Invalid Token"})
            return response, 401
        get_obj=job_obj.find({"user_id" : user_obj["id"]})
        res=[]
        for i in get_obj:
            del i["_id"]
            res.append(i)
        if get_obj:
            response = jsonify({'data': res, 'message': "You have got the User Details."})
            return response, 200
        else:
            response = jsonify({'data': None, 'message': 'You have not got the User Details.'})
            return response, 400
        
    @reviewers.route('/creator/<creator_id>/posted-jobs', methods=['GET'])
    @token_required
    def getJobCreateByCreatorID(creator_id):
        job_obj = mongo.db.jobs
        data_filter = {}
        data_filter["user_id"] = creator_id
        query_param = request.args
        app_obj=mongo.db.applicants
        url = "https://stage-api.billionviews.ai/creator/{}/posted-jobs/".format(creator_id)
        if 'status' in query_param and query_param['status'] != 'all': 
            data_filter['status'] = query_param['status']
            url += '?status={}'.format(query_param['status'])

        if 'date-posted' in query_param:
            pass
            # data_filter['date-posted'] = query_param['date-posted']

        get_obj=job_obj.find(data_filter)
        res=[]
        for i in get_obj:
            job_data = {}
            job_data['id'] = str(ObjectId(i['_id']))
            job_data['title'] = i.get("title","")
            job_data['category'] = i.get("category","")
            job_data['duration'] = i.get("duration","")
            job_data['budget'] = i.get("budget","")
            job_data['deadline'] = i.get("deadline","")
            job_data['createdAt'] = i.get("createdAt","")
            job_data['applicantsCount'] = app_obj.count_documents({"job_id":str(i["_id"])})
            job_data['projectType'] = i.get("projectType","")
            job_data['jobSite'] = i.get("jobSite","")
            res.append(job_data)
        
        start = query_param.get('start')
        limit = query_param.get('limit')
        data_obj=sorted(res, key=lambda d:d["createdAt"], reverse = True)

        if start and limit:
            res = get_paginated_list(data_obj, url, start, limit)
            if res is False:
                response = jsonify({'data': [], 'message': "No Jobs found."})
                return response, 200
        else:
            res = res

        if get_obj:
            response = jsonify({'data': res, 'message': "Jobs Fetched Successfully."})
            return response, 200
        else:
            response = jsonify({'data': None, 'message': 'Something went wrong.'})
            return response, 400
        
    @reviewers.route('/creator/<creator_id>/profile', methods=['GET'])
    @token_required
    def fetchProfileByCreatorID(creator_id):
        job_obj = mongo.db.users
        chat_obj = mongo.db.chatroom
        get_obj=job_obj.find_one({"_id" : ObjectId(creator_id)})
        if get_obj is None:
            response = jsonify({'data': None, 'message': 'Creator not found.'})
            return response, 400
        job_obj = mongo.db.jobs
        profile = {}
        profile['firstName'] = get_obj.get("firstName","")
        profile['lastName'] = get_obj.get("lastName","")
        profile['email'] = get_obj.get("email","")
        profile['phone'] = get_obj.get("phone","")
        profile['portfolio'] = get_obj.get("portfolio","")
        profile['contacts'] = get_obj.get("contacts","")
        profile['bio'] = get_obj.get("bio","")
        profile['postsCount'] = job_obj.count_documents({"user_id":creator_id})
        profile['editorsCount'] = chat_obj.count_documents({"sender":creator_id, "offer_status":"accepted"})
        response = jsonify({'data': profile, 'message': "Creator Profile Fetched."})
        return response, 200
        
    @reviewers.route('/creator/<creator_id>/general-profile', methods=['GET'])
    # @token_required
    def fetchCreatorGeneralProfile(creator_id):
        user_obj = mongo.db.users
        chat_obj = mongo.db.chatroom
        get_obj=user_obj.find_one({"_id" : ObjectId(creator_id)})
        if get_obj is None:
            response = jsonify({'data': None, 'message': 'Creator not found.'})
            return response, 400
        job_obj = mongo.db.jobs
        general_profile = {}
        general_profile['firstName'] = get_obj.get("firstName","")
        general_profile['lastName'] = get_obj.get("lastName","")
        general_profile['type'] = get_obj.get("type","")
        general_profile['profile_picture'] = get_obj.get("profile_picture","")
        general_profile['contacts'] = get_obj.get("contacts","")
        general_profile['bio'] = get_obj.get("bio","")
        general_profile['jobsCount'] = job_obj.count_documents({"user_id":creator_id})
        general_profile['postsCount'] = job_obj.count_documents({"user_id":creator_id})
        general_profile['editorsCount'] = chat_obj.count_documents({"sender":creator_id, "offer_status":"accepted"})
        response = jsonify({'data': general_profile, 'message': "Creator Profile Fetched."})
        return response, 200
        
        
    @reviewers.route('/creator/<creator_id>/contacts', methods=['PUT'])
    @token_required
    def updateCreatorContact(creator_id):
        user_obj = mongo.db.users
        req_body = request.get_json()
        update_req_body = {}
        update_req_body['contacts'] = req_body
        find_obj=user_obj.find_one({'_id':ObjectId(creator_id)})
        if find_obj is None:
            response = jsonify({'data': None, 'message': 'Creator Id not present.'})
            return response, 400
        get_obj = user_obj.update_one({"_id":ObjectId(creator_id)},{"$set":update_req_body})
        print(get_obj)
        response = jsonify({'message': "Contact Updated Sucessfully."})
        return response, 200
        
    @reviewers.route('/creator/<creator_id>/jobs/titles', methods=['GET'])
    @token_required
    def fetchCreatorJobTitleId(creator_id):
        job_obj = mongo.db.jobs
        get_record = job_obj.find({"user_id":creator_id})

        res=[]
        for i in get_record:
            
            data={
                "id":str(ObjectId(i['_id'])),
                "title" : i.get("title",""),
            }
            res.append(data)

        if get_record:
            response = jsonify({'title': res, 'message': "You have got the Job title and ID."})
            return response, 200
        else:
            response = jsonify({'data': None, 'message': 'You have not got the Job title and ID'})
            return response, 400
        

    #<----------------------------------------Applicants---------------------------->

    @reviewers.route('/creator/<creator_id>/applications/reject/<application_id>', methods=['DELETE'])
    def delapplicationByID(creator_id, application_id):
        print('=============')
        app_obj = mongo.db.applicants
        res = {"is_reject":True, "is_active":False, 'status':'rejected'}
        doc = app_obj.update_one({"_id":ObjectId(application_id)},{"$set":res})
        if doc:
            response = jsonify({'data': "OK", 'message': "Application has been Deleted."})
            return response, 200
        else:
            response = jsonify({'data': None, 'message': 'Application Id is wrong.'})
            return response, 400
        
    @reviewers.route('/creator/<creator_id>/applications/reject/', methods=['DELETE'])
    def delMultipleApplicationByCreatorID(creator_id):
        print('=============')
        app_obj = mongo.db.applicants
        req_body = request.get_json()
        applicant_list = req_body["applicants"]
        res = {"is_reject":True, "is_active":False, 'status':'rejected'}
        for applicants in applicant_list: 
            try:
                doc = app_obj.update_one({"_id":ObjectId(applicants)},{"$set":res})
            except:
                pass

        response = jsonify({'data': "OK", 'message': "All Application has been Deleted."})
        return response, 200
    @reviewers.route('/creator/<creator_id>/new-applications', methods=['GET'])
    @token_required
    def fetchCreatorNewApplicationsByID(creator_id):
        print("---------------------------------")
        app_obj = mongo.db.applicants
        job_obj=mongo.db.jobs
        user_obj=mongo.db.users
        query_param = request.args

        data_fiter={"user_id":creator_id}
        user_jobs_obj = job_obj.find(data_fiter)
        
        res=[]
        for i in user_jobs_obj:
            applicant_objs = app_obj.find({"job_id":str(i["_id"])})
            print(applicant_objs)
            if applicant_objs is not None:
                for applicant_obj in applicant_objs:
                    is_rejected = applicant_obj.get("is_reject",False)
                    
                    if is_rejected is False:
                        user=user_obj.find_one({"_id":ObjectId(applicant_obj["editor_id"])})
                        if user is not None and applicant_obj['status'] == 'active':
                            data={}
                            data["id"]=str(ObjectId(applicant_obj['_id']))
                            data["applicant"]={
                                "firstName":user.get("firstName",""),
                                "lastName":user.get("lastName",""),
                                "profile_picture":user.get("profile_picture",""),
                                "type":user.get("type","")
                            }

                            data["title"]=i.get("title","")
                            data["sampleVideo"]=applicant_obj.get("sampleVideo")
                            data["projectType"]=i.get("projectType","")
                            data["job_id"]=applicant_obj.get("job_id","")
                            data["pastVideos"]=applicant_obj.get("pastVideos")
                            data["projectFile"]=applicant_obj.get("projectFile")
                            data["rating"]=applicant_obj.get("rating","NA")
                            data["completion_percentage"]=calc_application_completion(applicant_obj)

                            res.append(data)
                    else:
                        print(is_rejected)
        url = "https://stage-api.billionviews.ai/creator/{}/new-applications".format(creator_id)
        start = query_param.get('start')
        limit = query_param.get('limit')

        if start and limit:
            print("---------------------------------")
            res = get_paginated_list(res, url, start, limit)
            if res is False:
                response = jsonify({'data': [], 'message': "No Jobs found."})
                return response, 200
        else:
            res = res

        response = jsonify({'data':res, 'message': "Job Fetched Successfully."})
        return response, 200
    
    @reviewers.route('/creator/<creator_id>/applications/<application_id>', methods=['GET'])
    @token_required
    def fetchApplicationsSubmissionFilesByID(creator_id, application_id):
        app_obj = mongo.db.applicants
        
        application_obj = app_obj.find_one({"_id":ObjectId(application_id)})
        if not application_obj:
            response = jsonify({'data': None, 'message': 'ID Not Found.'})
            return response, 400
        else:
            res=[]
            data={}
            data['submission'] = {
                "editor_id" : application_obj.get('editor_id'),
                "sampleVideo":application_obj.get("sampleVideo",""),
                "projectFile":application_obj.get("projectFile",""),
                "hasSubmission" : True,
                "pastVideos" : application_obj.get("pastVideos",""),
                "submissionDate" : application_obj.get("createdAt",""),
                "job_id":application_obj.get("job_id",""),
                "rating":application_obj.get("rating","NA"),
                "completion_percentage":calc_application_completion(application_obj),
            }
            res.append(data)

        response = jsonify({'data':res, 'message': "Job Fetched Successfully."})
        return response, 200
    

    # <-----------------------------------------------------Aquire------------------------------------------------------->

    @reviewers.route('/creator/<creator_id>/fetch-token-count', methods=['GET'])
    # @token_required
    def fetchTokenCount(creator_id):
        usr = mongo.db.users
        user_obj = usr.find_one({"_id":ObjectId(creator_id)})
        if user_obj:
            if 'tokensAcquired' in user_obj and (int(user_obj['tokensAcquired']) > 0):
                return jsonify({'data': {"tokensAcquired": int(user_obj['tokensAcquired'])}}), 200
            return jsonify({'data': {"tokensAcquired": 0}}), 200
        else:
            return jsonify({'message': "User Not Found!"}), 400

    @reviewers.route('/creator/<creator_id>/acquire/<editor_id>', methods=['POST'])
    # @token_required
    def acquireEditor(creator_id, editor_id):
        req_params = request.args
        if 'job_id' not in req_params:
            return jsonify({'message': "Please provide Job ID in request."}), 400
        #check for duplicacy
        chat_obj = mongo.db.chatroom
        # archived_chat_obj = mongo.db.archived_chatroom
        # dup_obj = chat_obj.count_documents({"sender":creator_id, "receiver":editor_id, "acquisitionStatus": {"$ne" : False}, "editor_response": {"$ne" : False}})
        dup_obj = chat_obj.count_documents({"sender":creator_id, "receiver":editor_id, "$or": [{"offer_status" : "pending"}, {"offer_status" : "accepted"}, {"offer_status" : "uninitialized"}]})
        if dup_obj:
                return jsonify({'message': "Aqcuisition already sent or chat room already created."}), 400
        
        
        usr = mongo.db.users
        user_obj = usr.find_one({"_id":ObjectId(creator_id)})
        
        if 'tokensAcquired' in user_obj and (int(user_obj['tokensAcquired']) > 0):

            # non_responded_chat_requests = chat_obj.find({"sender":creator_id, "acquisitionStatus":None, "editor_response": {"$ne" : False}})
            # non_responded_chat_requests_count = chat_obj.count_documents({"sender":creator_id, "acquisitionStatus":None, "editor_response": {"$ne" : False}})

            non_responded_chat_requests = chat_obj.find({"sender":creator_id, "$or": [{"offer_status" : "pending"},{"offer_status" : "uninitialized"}]})
            non_responded_chat_requests_count = chat_obj.count_documents({"sender":creator_id, "$or": [{"offer_status" : "pending"},{"offer_status" : "uninitialized"}]})

            final_unresponed_times = []
            request_eligible = False
            if non_responded_chat_requests_count >= int(user_obj['tokensAcquired']):
                for non_responded_chat_request in non_responded_chat_requests:
                    room_creation_date = parser.parse(non_responded_chat_request['createdAt'])
                    now_time = datetime.datetime.now()
                    t = now_time - room_creation_date
                    if t.days >= 2:
                        upd_chatroom = chat_obj.update_one({"_id":non_responded_chat_request['_id']},{"$set":{"editor_response":False, "offer_status":"expired"}})
                        # archive_obj = {'chatroom_obj':non_responded_chat_request, 'createdAt':datetime.datetime.now().isoformat()}
                        # archived_chat_obj.insert_one(archive_obj)
                        # chat_obj.delete_one({"_id":ObjectId(non_responded_chat_request['_id'])})
                        request_eligible = True
                        break
                    else:
                        
                        final_unresponed_times.append(t)
            else:
                request_eligible = True
            

            if request_eligible is False:
                final_unresponed_times = str(timedelta(days=2) - sorted(final_unresponed_times, reverse=True)[0])
                final_str = humanize_date(final_unresponed_times)
                return jsonify({'message': "Please wait for Editor's to accept previous request or wait for {} or Buy new tokens!".format(final_str)}), 400

            req_body = request.get_json()
            if req_body is None:
                req_body = {}
            req_body['sender'] = creator_id
            req_body['receiver'] = editor_id
            req_body['job_id'] = req_params['job_id']
            req_body['paymentStatus'] = None
            req_body['acquisitionStatus'] = None
            req_body['editor_response'] = None
            req_body['editor_response_time'] = None
            req_body['offer_status'] = "uninitialized"     #Offer status: uninitialized,  pending (Waiting for reply), rejected, accepted, expired
            req_body['acquisitionTime'] = ""
            req_body['termsStatus'] = None
            req_body['createdAt'] = datetime.datetime.now().isoformat()
            req_body['isLastMessageSeen']= ""
            req_body['lastMessage']= ""
            req_body['lastSeen']= ""
            req_body['unreadMessagesCount']= ""
            req_body['lastMessageTime']= ""

            chat_obj.insert_one(req_body)

            #fetching editor details from editor ID

            editor_obj = usr.find_one({"_id":ObjectId(editor_id)})

            req_body["userId"] = str(editor_obj["_id"])
            req_body["firstName"] = editor_obj.get("firstName","")
            req_body["lastName"] = editor_obj.get("lastName","")
            req_body["profile_picture"] = editor_obj.get("profile_picture","")
            req_body["type"] = editor_obj.get("type","")

            req_body["_id"] = str(req_body["_id"])
            req_body["chat_room_id"] = str(req_body["_id"])
            response = jsonify({'data': req_body, 'message': "Editor Aquisition Sent Successfully."})
            return response, 200
        else:
            return jsonify({'message': "Insufficient Tokens!"}), 400
    
    @reviewers.route('/editor/<editor_id>/acquisition/<creator_id>', methods=['PUT']) # please send chatroom ID 
    # @token_required
    def acceptCreatorAcquisition(editor_id, creator_id):
        
        req_param = request.args
        chat_obj = mongo.db.chatroom
        jobs = mongo.db.jobs
        if 'chat_room_id' not in req_param:
            return jsonify({'message': "Please provide Chat Room ID"}), 400

        chatroom_obj = chat_obj.find_one({"_id":ObjectId(req_param['chat_room_id'])})
        if not chatroom_obj:
            return jsonify({'message': "Chatroom not found"}), 400
        
        sender_receiver = sorted([chatroom_obj['sender'], chatroom_obj['receiver']])
        request_sender_receiver = sorted([editor_id, creator_id])

        if sender_receiver != request_sender_receiver:
            return jsonify({'message': "There is some mismatch in chatroom and sender/receiver, please check request."}), 400

        if chatroom_obj['offer_status'] == "rejected":
            return jsonify({'message': "Offer already Rejected."}), 400
        elif chatroom_obj['offer_status'] == "expired":
            return jsonify({'message': "Offer Expired."}), 400
        elif chatroom_obj['offer_status'] == "accepted":
            return jsonify({'message': "Offer already Accepted."}), 400
        
        elif chatroom_obj['offer_status'] in ["uninitialized","pending"]:
            room_creation_date = parser.parse(chatroom_obj['createdAt'])
            now_time = datetime.datetime.now()
            t = now_time - room_creation_date
            if t.days >= 2:
                upd_chatroom = chat_obj.update_one({"_id":chatroom_obj['_id']},{"$set":{"editor_response":False, "offer_status":"expired"}})
                return jsonify({'message': "Offer Expired!"}), 400
            


            if req_param['accept'] is True or req_param['accept'] == 'true':
                # check creator token and subtract token

                usr = mongo.db.users
                user_obj = usr.find_one({"_id":ObjectId(creator_id)})

                if 'tokensAcquired' in user_obj and int(user_obj['tokensAcquired']) > 0:
                    upd_obj = {'tokensAcquired' : int(user_obj['tokensAcquired'])-1}
                    usr.update_one({"_id":ObjectId(creator_id)},{"$set":upd_obj})
                    tran_obj = mongo.db.transactions
                    inp_data = {
                        "user_id":creator_id,
                        "payment_body":{},
                        "symbol":"-",
                        "createdAt" : datetime.datetime.now().isoformat(),
                        "tokensAcquired":1,
                        "description":"Successfully acquired editor - {}.".format(editor_id)
                    }
                    tran_obj.insert_one(inp_data)
                    now_time = datetime.datetime.now().isoformat()
                    chat_obj.update_one({"_id":chatroom_obj["_id"]},{"$set":{"acquisitionStatus":True, "acquisitionTime":now_time, "editor_response":True, "editor_response_time":now_time, "offer_status":"accepted"}})
                    # update job status
                    jobs.update_one({"_id":ObjectId(chatroom_obj["job_id"])},{"$set":{"status":"hired"}})
                else:
                    return jsonify({'message': "Creator don't have tokens"}), 400
            else:
                now_time = datetime.datetime.now().isoformat()
                chat_obj.update_one({"_id":chatroom_obj["_id"]},{"$set":{"acquisitionStatus":False, "editor_response":True, "editor_response_time":now_time, "offer_status":"rejected"}})

            response = jsonify({'message': "Editor Aquisition Status Updated Successfully."})
            return response, 200
        else:
            return jsonify({'message': "Wrong Offer Status!"}), 400
        
    
    @reviewers.route('/creator/report', methods=['POST']) 
    @token_required
    def report_editor():
        try:
            token = request.headers.get('Authorization')
            decoded_token = getID(token)
            reports = mongo.db.reports
            req_body = request.get_json()
            req_param = request.args
            if 'user_id' not in req_param or 'type' not in req_param:
                return {"message":"Please provide all mandatory fields!"}, 400
            dup_obj = reports.count_documents({"user_id":req_param['user_id'],"reporter_id":decoded_token['id']})
            if dup_obj:
                return {"message":"You have already reported on this user!"}, 400
            req_body['reporter_id'] = decoded_token['id']
            req_body['reporter_type'] = decoded_token['type']
            req_body['report_type'] = "user"
            req_body['user_id'] = req_param["user_id"]
            req_body['user_type'] = req_param["type"]
            
            reports.insert_one(req_body)
            create_report_task(req_body)
            return {"message":"Reported Successfully."}, 201
        except Exception as e:
            print(str(e))
            return {"message":"Something went wrong!"}, 201
    
    return reviewers

