from flask import Blueprint, request, jsonify
from bson import json_util, objectid
from functools import wraps
from bson import objectid
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import jwt
from .schema import LoginSchema, RegisterSchema
from settings import SALT
SECRET_KEY = SALT
import datetime
from random import randint
from utils.util import getID, generateOTP, generateVerificationLink, encrypt, decrypt, get_paginated_list, calc_application_completion, create_clickup_subtask
from bson import ObjectId
import re
from dateutil import parser
from decouple import config
import requests
import json

def editors_bp(mongo, mail):

    editors = Blueprint('editors', 'editors', __name__)

    
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

    @editors.route('/editor/login', methods=['POST'])
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
        
        editors = mongo.db.editors
        
        filter = {'email': req_body['email']}
        e = editors.find_one(filter)
        is_active = e.get("is_active")
        email_verified = e.get("email_verified")
        if not e:
            response = jsonify({'data': None, 'message': 'Invalid email and password.'})
            return response, 401

        else:
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
                del claims['_id']
                del claims['password']
                claims['expiry'] = str(datetime.datetime.utcnow() + timedelta(days=30))
                del e['expiry']
                del e["otp"]
                del e["email_verified"]
                del e ["otp_exp"]
                del e["is_active"]
                token = jwt.encode(claims, SALT)
                response = jsonify({'message': 'Login Successfully.', 'data': e, 'token': token})
                return response, 200
            else :
                response = jsonify({'data': None, 'message': 'Incorrect Password.'})
                return response, 401

        
    @editors.route('/editor/register', methods=['POST'])
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
       
        editors = mongo.db.editors
        employers = mongo.db.employers
        filter = {'email': req_body['email']}
        e = editors.find_one(filter)
        if e:
            response = jsonify({
                'data': None,
                'message': 'This email is already registered.'
            })
            return response, 401

        
        pass_hash = generate_password_hash(req_body['password'])
        if req_body["type"] != "editor":
            data={"message" : "Type must be Editor."}
            return data
        else:
            e = {
                'email': req_body['email'],
                'firstName': req_body['firstName'],
                'lastName': req_body['lastName'],
                'password': pass_hash,
                'type': req_body["type"],
                'contacts':{}
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


    @editors.route('/editor/verify-email', methods=['POST'])
    def VerifyEmail():
        req_body = request.get_json()
        editors = mongo.db.editors
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
        

    @editors.route('/editor/update-profile', methods=['PUT'])
    @token_required
    def UpdateProfile():
        req_body = request.get_json()
        editors = mongo.db.editors
        
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

    
    @editors.route('/editor/change-password', methods=['PUT'])
    @token_required
    def change_password():
        token = request.headers.get('Authorization')
        
        get_obj= getID(token)
        req_body = request.get_json()
        editors = mongo.db.editors
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
        
    
    @editors.route('/editor/forget-password-link', methods=['POST'])
    def GetForgotPasswordLink():
        req_body = request.get_json()
        edit_obj = mongo.db.editors
        message=req_body["email"]
        enc_mail= encrypt(message)
        editor_obj = {}
        editor_obj["verified_link"] = True
        edit_obj.update_one({"email":message}, {"$set":editor_obj})
        verification_link="google.com?={}".format(enc_mail)
        email_status = generateVerificationLink(mail, req_body['email'], verification_link)
        if email_status is True:
            response = jsonify({'data': None, 'message': "Forget Password Link Sent to your Email."})
        else:
            response = jsonify({'data': None, 'message': "Forget Password Link Not Sent to your Email."})
        return response, 201
    
    @editors.route('/editor/forget-password', methods=['POST'])
    def ForgotPassword():
        req_body = request.get_json()
        enc_mail=req_body["resetToken"]
        email= decrypt(enc_mail)
        editor = mongo.db.editors
        editor_obj = editor.find_one({"email":email})
        if editor_obj["verified_link"] is True:
            password_hash = generate_password_hash(str(req_body['newPassword']))
            editor.update_one({"email":email},{"$set":{"password":password_hash,"verified_link":False}})
            response = jsonify({'data': None, 'message': "Forget Password Successfully."})
            return response, 200
        else:
            response = jsonify({'data': None, 'message': 'Link Expired!'})
            return response, 400
        

#<----------------------------------------------------Applicants----------------------------------------->

    @editors.route('/editor/<editor_id>/apply', methods=['POST'])
    @token_required
    def applyJobByJobID(editor_id):
        users = mongo.db.users
        user_obj = users.find_one({"_id":ObjectId(editor_id)})
        if not user_obj:
            return jsonify({'message': 'Invalid Editor!'}), 400  
        app_obj = mongo.db.applicants
        job_obj = mongo.db.jobs
        req_param = request.args
        req_body = request.get_json()
        if "job_id" not in req_param:
            return jsonify({'message': 'Please provide job_id in request params.'}), 400  

        application_job_obj = job_obj.find_one({"_id":ObjectId(req_param['job_id'])})
        
        if application_job_obj['status'] != "active":
            return jsonify({'message': 'Job is not active.'}), 400  

        updated_record = app_obj.find_one({"editor_id":editor_id, "job_id":req_param['job_id']})
        if updated_record:
            response = jsonify({'data': None, 'message': 'Editor has already applied to this job.'})
            return response, 400 
        data={}
        data["sampleVideo"]=req_body["sampleVideo"]
        data["projectFile"]=req_body["projectFile"]
        data["pastVideos"]=req_body["pastVideos"]
        data["editor_id"]=editor_id
        data["createdAt"]=datetime.datetime.now().isoformat()
        data["job_id"]=req_param['job_id']
        data["is_reject"]=False
        data["is_active"]=True
        data["status"]='active'
        data["rating"]='NA'
        doc = app_obj.insert_one(data)

        if doc:
            
            clickup_task_id = application_job_obj.get("clickup_task_id")
            # job_creation_date = application_job_obj.get("createdAt")
            if clickup_task_id:
                data["editor_name"] = user_obj.get("firstName","") + ' ' + user_obj.get("lastName","")
                clickup_sub_task_id = create_clickup_subtask(data, clickup_task_id)
                app_obj.update_one({"_id":data["_id"]},{"$set":{"clickup_sub_task_id":clickup_sub_task_id}})
            response = jsonify({'message': "Applicants Created Successfully."})
            return response, 200
        else:
            response = jsonify({'message': 'Something went wrong.'})
            return response, 400  
        
    @editors.route('/editor/<editor_id>/applied-jobs/', methods=['GET'])
    # @token_required
    def fetchEditorAppliedJobsByID(editor_id):
        applicants_obj = mongo.db.applicants
        job_obj = mongo.db.jobs
        data_filter={}
        query_param = request.args
        url = "https://stage-api.billionviews.ai/editor/{}/applied-jobs/".format(editor_id)
        if 'status' in query_param and query_param['status'] != 'all':
            data_filter['status'] = query_param['status']
            url += '?status={}'.format(query_param['status'])

        if 'date-posted' in query_param:
            pass
        data_filter['editor_id'] = editor_id
        app_obj=applicants_obj.find(data_filter)
        res=[]
        for i in app_obj:
            jobs_obj=job_obj.find_one({"_id":ObjectId(i["job_id"])})
            if jobs_obj is not None:
                print(i)
                job_data = {}
                job_data['id'] = str(ObjectId(jobs_obj['_id']))
                job_data['title'] = jobs_obj.get("title","")
                job_data['category'] = jobs_obj.get("category","")
                job_data['duration'] = jobs_obj.get("duration","")
                job_data['budget'] = jobs_obj.get("budget","")
                job_data['deadline'] = jobs_obj.get("deadline","")
                job_data['createdAt'] = jobs_obj.get("createdAt","")
                job_data['projectType'] = jobs_obj.get("projectType","")
                job_data['hasSample'] = True if i['sampleVideo'] else False
                job_data['jobSite'] = jobs_obj.get("jobSite","")
                job_data['hasPastVideos'] = True if i['pastVideos'] else False
                job_data['active'] = jobs_obj.get("active",True)
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

        if res:
            response = jsonify({'data': res, 'message': "Jobs Fetched Successfully."})
            return response, 200
        else:
            response = jsonify({'data': None, 'message': 'Jobs not Found.'})
            return response, 400
        
    @editors.route('/editor/<editor_id>/profile', methods=['GET'])
    @token_required
    def fetchProfileByEditorID(editor_id):
        job_obj = mongo.db.users
        get_obj=job_obj.find_one({"_id" : ObjectId(editor_id)})
        app_obj=mongo.db.applicants
        if get_obj is None:
            response = jsonify({'data': None, 'message': 'Editor not found.'})
            return response, 400        
        profile = {}
        profile['firstName'] = get_obj.get("firstName","")
        profile['lastName'] = get_obj.get("lastName","")
        profile['email'] = get_obj.get("email","")
        profile['phone'] = get_obj.get("phone","")
        profile['portfolio'] = get_obj.get("portfolio","")
        profile['contacts'] = get_obj.get("contacts","")
        profile['bio'] = get_obj.get("bio","")
        profile['applicationCount'] = app_obj.count_documents({"editor_id":editor_id})
        response = jsonify({'data': profile, 'message': "Editor Profile Fetched."})
        return response, 200
    
    @editors.route('/editor/<editor_id>/contacts', methods=['PUT'])
    @token_required
    def updateEditorContact(editor_id):
        user_obj = mongo.db.users
        req_body = request.get_json()
        updated_req_body = {}
        updated_req_body['contacts'] = req_body
        find_obj=user_obj.find_one({'_id':ObjectId(editor_id)})
        if find_obj is None:
            response = jsonify({'data': None, 'message': 'Editor Id not present.'})
            return response, 400
        get_obj = user_obj.update_one({"_id":ObjectId(editor_id)},{"$set":updated_req_body})
        response = jsonify({'message': "Contact Updated Sucessfully."})
        return response, 200
    
    @editors.route('/editor/<editor_id>/general-profile', methods=['GET'])
    @token_required
    def fetchEditorGeneralProfile(editor_id):
        user_obj = mongo.db.users
        get_obj=user_obj.find_one({"_id" : ObjectId(editor_id)})
        app_obj=mongo.db.applicants
        if get_obj is None:
            response = jsonify({'data': None, 'message': 'Editor not found.'})
            return response, 400
        general_profile = {}
        general_profile['firstName'] = get_obj.get("firstName","")
        general_profile['lastName'] = get_obj.get("lastName","")
        general_profile['type'] = get_obj.get("type","")
        general_profile['profile_picture'] = get_obj.get("profile_picture","")
        general_profile['contacts'] = get_obj.get("contacts","")
        general_profile['portfolio'] = get_obj.get("portfolio","")
        general_profile['bio'] = get_obj.get("bio","")
        general_profile['email'] = get_obj.get("email","")
        general_profile['applicationsCount'] = app_obj.count_documents({"editor_id":editor_id})
        response = jsonify({'data': general_profile, 'message': "Editor Profile Fetched."})
        return response, 200

    @editors.route('/jobs/search', methods=['GET'])
    def fetchJobs():
        job_obj = mongo.db.jobs
        query_param=request.args
        data_fiter={}
        url = "https://stage-api.billionviews.ai/jobs/search"

        if "query" in query_param:
            rgx = re.compile('.*{}.*'.format(query_param['query']), re.IGNORECASE)
            data_fiter['$or'] = [{"title":rgx},{"category":rgx},{"budget":rgx}]
            url += '?query={}'.format(query_param['query'])
            
        if "category" in query_param and  query_param["category"] != "all":
            data_fiter['category'] = query_param['category']
            if '?' in url:
                url += '&category={}'.format(query_param['category'])
            else:
                url += '?category={}'.format(query_param['category'])

        if "frequency" in query_param:
            data_fiter['projectFrequency'] = query_param['frequency']
            if '?' in url:
                url += '&frequency={}'.format(query_param['frequency'])
            else:
                url += '?frequency={}'.format(query_param['frequency'])
        
        if "duration" in query_param:
            print(query_param['duration'])
            data_fiter['duration'] = query_param['duration']
            if '?' in url:
                url += '&duration={}'.format(query_param['duration'])
            else:
                url += '?duration={}'.format(query_param['duration'])

        if "maxBudget" in query_param:
            data_fiter['budget'] = {"$lte": int(query_param['maxBudget'])} 
            if '?' in url:
                url += '&maxBudget={}'.format(query_param['maxBudget'])
            else:
                url += '?maxBudget={}'.format(query_param['maxBudget'])
            
        if "minBudget" in query_param:
            data_fiter['budget'] = {"$gte": int(query_param['minBudget'])} 
            if '?' in url:
                url += '&minBudget={}'.format(query_param['minBudget'])
            else:
                url += '?minBudget={}'.format(query_param['minBudget'])

        if "software" in query_param:
            data_fiter['editingSoftware'] = { "$in": [query_param['software']] } 

            if '?' in url:
                url += '&software={}'.format(query_param['software'])
            else:
                url += '?software={}'.format(query_param['software'])

        if "date-posted" in query_param:
            curr_date = datetime.datetime.now()
            # any-time | past-24-hour | past-week | past-month | past-year
            if query_param['date-posted'] == 'past-24-hour':
                check_date = curr_date - timedelta(days=1)
            elif query_param['date-posted'] == 'past-week':
                check_date = curr_date - timedelta(days=7)
            elif query_param['date-posted'] == 'past-month':
                check_date = curr_date - timedelta(days=30)
            elif query_param['date-posted'] == 'past-year':
                check_date = curr_date - timedelta(days=365)
            else:
                pass

            if query_param['date-posted'] in ["past-24-hour" , "past-week" , "past-month" , "past-year"]:
                data_fiter['createdAt'] = {"$gte": str(check_date)}
            if '?' in url:
                url += '&date-posted={}'.format(query_param['date-posted'])
            else:
                url += '?date-posted={}'.format(query_param['date-posted'])

        get_obj=job_obj.find(data_fiter)
        res=[]
        for i in get_obj:
            job_data = {}
            job_data['id'] = str(ObjectId(i['_id']))
            job_data['title'] = i.get("title","")
            job_data['category'] = i.get("category","")
            job_data['duration'] = i.get("duration","")
            job_data['budget'] = i.get("budget","")
            job_data['projectType'] = i.get("projectType","")
            res.append(job_data)
        
        start = query_param.get('start')
        limit = query_param.get('limit')

        if start and limit:
            res = get_paginated_list(res, url, start, limit)
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
        
    @editors.route('/jobs/<job_id>', methods=['GET'])
    # @token_required
    def fetchJobById(job_id):
        job_obj = mongo.db.jobs
        get_obj=job_obj.find_one({"_id" : ObjectId(job_id)})
        app_obj=mongo.db.applicants
        if get_obj is None:
            response = jsonify({'data': None, 'message': 'Job not found.'})
            return response, 400        
        profile = {}
        profile["creatorId"] = str(ObjectId(get_obj['user_id']))
        profile['title'] = get_obj.get("title","")
        profile['category'] = get_obj.get("category","")
        profile['duration'] = get_obj.get("duration","")
        profile['budget'] = get_obj.get("budget","")
        profile['deadline'] = get_obj.get("deadline","")
        profile['createdAt'] = get_obj.get("createdAt","")
        profile['requestSample'] = get_obj.get("requestSample","")
        profile['sampleEdit'] = get_obj.get("sampleEdit","")
        profile['requestPastVideos'] = get_obj.get("requestPastVideos","")
        profile['referenceVideos'] = get_obj.get("referenceVideos","")
        profile['jobSite'] = get_obj.get("jobSite","")
        profile['editingSoftware'] = get_obj.get("editingSoftware","")
        profile['projectType'] = get_obj.get("projectType","")
        profile['projectFrequency'] = get_obj.get("projectFrequency","")
        profile['turnAroundTime'] = get_obj.get("turnAroundTime","")
        profile['paymentMethod'] = get_obj.get("paymentMethod","")
        profile['applicantsCount'] = app_obj.count_documents({"job_id":job_id})
        response = jsonify({'data': profile, 'message': "Job Fetched Successfully."})
        return response, 200
    
    @editors.route('/jobs/suggested-jobs', methods=['GET'])
    # @token_required
    def fetchSuggestedJobsfromJobID():
        job_obj = mongo.db.jobs
        req_param = request.args
        
        job_id = job_obj.find_one({"_id":ObjectId(req_param['job_id'])})
        cat=job_id["category"]
        if not cat:
            response = jsonify({'data': None, 'message': 'Category Not Found.'})
            return response, 400
        job_id = job_obj.find({"category":cat})
        res=[]
        for i in job_id:
            data={}
            data["title"]=i.get("title","")
            data["category"]=i.get("category","")
            data["duration"]=i.get("duration", "")
            data["budget"]=i.get("budget","")
            data["projectType"]=i.get("projectType","")
            data["jobSite"]=i.get("jobSite","")
            data["id"]=str(ObjectId(i['_id']))
            res.append(data)
        
        start = req_param.get('start')
        limit = req_param.get('limit')
        url = "https://stage-api.billionviews.ai/jobs/suggested-jobs?job_id={}".format(req_param['job_id'])

        if start and limit:
            res = get_paginated_list(res, url, start, limit)
            if res is False:
                response = jsonify({'data': [], 'message': "No Jobs found."})
                return response, 200
        else:
            res = res

        if data:
            response = jsonify({'data':res, 'message': "Job Fetched Successfully."})
            return response, 200
        else:
            response = jsonify({'message': 'Something went wrong.'})
            return response, 400
    
    @editors.route('/editor/<editor_id>/recent-jobs', methods=['GET'])
    @token_required
    def fetchEditorsRecentlyAppliedJobsByID(editor_id):
        app_obj = mongo.db.applicants
        job_obj=mongo.db.jobs
        editor_obj = app_obj.find({"editor_id":editor_id})
        
        res=[]
        for i in editor_obj:
            jobs_obj = job_obj.find_one({"_id":ObjectId(i["job_id"])})

            data={}
            data["id"]=str(ObjectId(i['_id']))
            data["title"]=jobs_obj.get("title","")
            data["category"]=jobs_obj.get("category","")
            data["duration"]=jobs_obj.get("duration", "")
            data["budget"]=jobs_obj.get("budget","")
            data["projectType"]=jobs_obj.get("projectType","")
            data["jobSite"]=jobs_obj.get("jobSite","")
            data["createdAt"] = i.get("createdAt")
            res.append(data)
        data_obj=sorted(res, key=lambda d:d["createdAt"], reverse = True)
        if len(data_obj) <= 5:
            pass
        else:
            data_obj = data_obj[:3]
        response = jsonify({'data':data_obj, 'message': "Job Fetched Successfully."})
        return response, 200
    

    @editors.route('/jobs/featured', methods=['GET'])
    # @token_required
    def fetchFeaturedJobs():
        job_obj = mongo.db.jobs
        job_id = job_obj.find()
        
        res=[]
        for i in job_id:
            data={}
            data["id"]=str(ObjectId(i['_id']))
            data["title"]=i.get("title","")
            data["category"]=i.get("category","")
            data["duration"]=i.get("duration", "")
            data["budget"]=i.get("budget","")
            data["deadline"]=i.get("deadline","")
            data["applicantsCount"]=""
            data["createdAt"]=i.get("createdAt","")
            data["projectType"]=i.get("projectType","")
            data["jobSite"]=i.get("jobSite","")
            res.append(data)

        data_obj=sorted(res, key=lambda d:d["createdAt"], reverse = True)        
        response = jsonify({'data':data_obj, 'message': "Job Fetched Successfully."})
        return response, 200
    
    # <------------------------------------------------------------------------------------------->

    # @editors.route('/editor/<editor_id>/new-contacts', methods=['GET'])
    # @token_required
    # def fetchEditorNewContacts():
    #     pass
        

    @editors.route('/editor/<editor_id>/applied', methods=['GET'])
    @token_required
    def fetchEditorApplicationStatus(editor_id):
        app_obj = mongo.db.applicants
        req_param = request.args
        if req_param["job_id"] is not None:
            job_id = app_obj.find_one({"editor_id":editor_id, 'job_id':req_param["job_id"]})
            if job_id is not None:
                response = jsonify({'applied': True})
                return response, 200
            else:
                response = jsonify({'applied': False})
                return response, 400                            
        else:
            response = jsonify({'message': 'Please Provide Job Id.'})
            return response, 400
    


    @editors.route('/creator/<creator_id>/applications', methods=['GET'])
    # @token_required
    def fetchCreatorApplications(creator_id):
        app_obj = mongo.db.applicants
        job_obj=mongo.db.jobs
        user_obj=mongo.db.users
        query_param=request.args
        data_fiter={"user_id":creator_id}
        url = "https://stage-api.billionviews.ai/creator/{}/applications?".format(creator_id)


        applicant_filter = {"is_reject" : False}
        if "status" in query_param and query_param['status'] != 'all':
            applicant_filter['status'] = query_param['status']
            
        
        
        if "job_id" in query_param:
            data_fiter['_id'] = ObjectId(query_param['job_id'])
            if '?' in url:
                url += '&job_id={}'.format(query_param['job_id'])
            else:
                url += '?job_id={}'.format(query_param['job_id'])

        user_jobs_obj = job_obj.find(data_fiter)
        
        res=[]
        start = query_param.get('start')
        limit = query_param.get('limit')
        for i in user_jobs_obj:
            applicant_filter['job_id'] = str(i["_id"])
            applicant_obj = app_obj.find_one(applicant_filter)
            if applicant_obj is not None:
                user=user_obj.find_one({"_id":ObjectId(applicant_obj["editor_id"])})
                if user is not None and applicant_obj['status'] == 'active':
                    data={}
                    # data["applications"] = {
                    #     "id" : str(ObjectId(applicant_obj['_id']))
                    # }
                    data["applicant"]={
                        "firstName":user.get("firstName",""),
                        "lastName":user.get("lastName",""),
                        "profile_picture":user.get("profile_picture",""),
                        "type":user.get("type",""),
                        "editorId" : str(user.get("_id", ""))

                    }
                    data["id"] = str(applicant_obj['_id'])
                    data["title"]=i.get("title","")
                    data["sampleVideo"]=applicant_obj.get("sampleVideo","")
                    data["projectFile"]=applicant_obj.get("projectFile","")
                    data["projectType"]=i.get("projectType","")
                    data["createdAt"]=applicant_obj.get("createdAt","")
                    data["pastVideos"]=applicant_obj.get("pastVideos","")
                    data["job_id"]=applicant_obj.get("job_id","")
                    data["rating"]=applicant_obj.get("rating","NA")
                    data["completion_percentage"]=calc_application_completion(applicant_obj)
                    res.append(data)
        
        data_obj=sorted(res, key=lambda d:d["createdAt"], reverse = True)
        if start and limit:
            res = get_paginated_list(data_obj, url, start, limit)
            if res is False:
                response = jsonify({'data': [], 'message': "No Jobs found."})
                return response, 200
        else:
            res = res

        response = jsonify({'data':res, 'message': "Job Fetched Successfully."})
        return response, 200


    # @editors.route('/chat/contacts/<user_id>', methods=['GET'])
    # @token_required
    # def fetchApplicationFilesBothWithApplicationIDAndEditorID():
    #     pass

    @editors.route('/jobs/other', methods=['GET'])
    def fetchOtherJobs():
        job_obj = mongo.db.jobs
        job_id = job_obj.find()
        query_param = request.args
        res=[]
        for i in job_id:
            data={}
            data["id"]=str(ObjectId(i['_id']))
            data["title"]=i.get("title","")
            data["category"]=i.get("category","")
            data["duration"]=i.get("duration", "")
            data["budget"]=i.get("budget","")
            data["createdAt"]=i.get("createdAt","")
            data["projectType"]=i.get("projectType","")
            res.append(data)

        url = "https://stage-api.billionviews.ai/jobs/suggested-jobs"
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

        response = jsonify({'data':res, 'message': "Job Fetched Successfully."})
        return response, 200
    
    @editors.route('/editor/<editor_id>/submissions', methods=['GET'])
    @token_required
    def fetchEditorApplicationFiles(editor_id):
        app_obj = mongo.db.applicants
        req_param = request.args
        
        application_obj = app_obj.find_one({"editor_id":editor_id, "job_id":req_param['job_id']})
        if not application_obj:
            response = jsonify({'data': None, 'message': 'ID Not Found.'})
            return response, 400
        else:
            res=[]
            data={}
            data['submission'] = {
                "sampleVideo":application_obj.get("sampleVideo",""),
                "projectFile":application_obj.get("projectFile",""),
                "hasSubmission" : True,
                "pastVideos" : application_obj.get("pastVideos",""),
                "submissionDate" : application_obj.get("createdAt","")

            }
            res.append(data)

        response = jsonify({'data':res, 'message': "Job Fetched Successfully."})
        return response, 200
    
    @editors.route('/chat/profile/<user_id>', methods=['GET'])
    @token_required
    def fetchChatProfileByID(user_id):
        user_obj = mongo.db.users
        get_obj=user_obj.find_one({"_id" : ObjectId(user_id)})
        if get_obj is None:
            response = jsonify({'data': None, 'message': 'ID not found.'})
            return response, 400
        general_profile = {}
        general_profile['firstName'] = get_obj.get("firstName","")
        general_profile['lastName'] = get_obj.get("lastName","")
        general_profile['type'] = get_obj.get("type","")
        general_profile['profile_Picture'] = get_obj.get("profile_Picture","")
        general_profile['contacts'] = get_obj.get("contacts","")
        general_profile['bio'] = get_obj.get("bio","")
        response = jsonify({'data': general_profile, 'message': "Profile Fetched Successfully."})
        return response, 200
    

    # <-------------------------------------------------------Messages--------------------------------------------------------->

    @editors.route('/chat/message/<user_id>', methods=['POST'])  # please send chatroom ID 
    # @token_required
    def sendMessageToUserWithID(user_id):
        chat_obj = mongo.db.chatroom
        msg_obj = mongo.db.messages
        req_body = request.get_json()
        req_param = request.args
        if 'chat_room_id' not in req_param:
            return jsonify({'message': "Please provide Chat Room ID"}), 400
    
        if 'to_user_id' not in req_param:
            return jsonify({'message': "Please provide to_user_id"}), 400
        
        
        message = req_body["message"]
        req_body["receiver"] = req_param["to_user_id"]
        req_body["sender"] = user_id
        req_body["createdAt"] = datetime.datetime.now().isoformat()
        del req_body["message"]
        #checking existing chatrooms
        ex1 = chat_obj.find_one({"_id":ObjectId(req_param['chat_room_id'])})
        if ex1 is None:
            return jsonify({'message': "Acquisition not sent"}), 400
        else:
            chat_room_id = ex1['_id']
            ex = ex1

        sender_receiver = sorted([ex['sender'], ex['receiver']])
        request_sender_receiver = sorted([user_id, req_param['to_user_id']])

        if sender_receiver != request_sender_receiver:
            return jsonify({'message': "There is some mismatch in chatroom and sender/receiver, please check request."}), 400

        msg_body ={
            "message" :  message,
            "chat_room_id" : str(chat_room_id),
            "sender" : user_id,
            "receiver" : req_param["to_user_id"],
            "createdAt" : datetime.datetime.now().isoformat(),
            "isSeen":False
        }


        # checking on the basis of offer status - 

        if ex['offer_status'] == "rejected":
            return jsonify({'message': "Aqcuisition is Rejected."}), 400
        elif ex['offer_status'] == "expired":
            return jsonify({'message': "Aqcuisition is Expired."}), 400
        elif ex['offer_status'] == "pending":
            if user_id == ex['sender']: # this is creator
                msg_obj.insert_one(msg_body)
                update_object = {"lastMessage":message, "lastMessageTime":msg_body['createdAt'], "isLastMessageSeen":False}
                chat_obj.update_one({"_id":ObjectId(chat_room_id)},{"$set":update_object})
            elif user_id == ex['receiver']: # this is editor
                return jsonify({'message': "Aqcuisition is Pending."}), 400

        elif ex['offer_status'] == "accepted":
            msg_obj.insert_one(msg_body)
            update_object = {"lastMessage":message, "lastMessageTime":msg_body['createdAt'], "isLastMessageSeen":False}
            chat_obj.update_one({"_id":ObjectId(chat_room_id)},{"$set":update_object})

        elif ex['offer_status'] == "uninitialized":
            if user_id == ex['sender']: # this is creator
                msg_obj.insert_one(msg_body)
                update_object = {"lastMessage":message, "lastMessageTime":msg_body['createdAt'], "isLastMessageSeen":False, "offer_status":"pending"}
                chat_obj.update_one({"_id":ObjectId(chat_room_id)},{"$set":update_object})
            elif user_id == ex['receiver']: # this is editor
                return jsonify({'message': "Please accept the offer first!."}), 400
        else:
            return jsonify({'message': "Wrong offer_status."}), 400
        
        # chat_obj.update_one({"_id":ObjectId(chat_room_id)},{{"$set":({"lastMessage":message, "lastMessageTime":msg_body['createdAt'], "isLastMessageSeen":False})}})
        response = jsonify({'message': "Message Sent Successfully."})
        return response, 200
    

    @editors.route('/chat/contacts/<user_id>', methods=['GET'])
    # @token_required
    def searchUserChatContacts(user_id):
        msg_obj = mongo.db.messages
        data = []
        chat_room_obj = mongo.db.chatroom

        user_obj = mongo.db.users
        req_param = request.args
        search_text = req_param.get('query',"")
        data_filter = {}
        rgx = re.compile('.*{}.*'.format(user_id), re.IGNORECASE)
        data_filter['$or'] = [{"sender":rgx},{"receiver":rgx}]
        all_chat_rooms = chat_room_obj.find(data_filter)
        print(all_chat_rooms)

        for chat_room in all_chat_rooms:
            print("-----------------------------------------------------")
            print(chat_room)
            print("--------------------------------------------")
            other_person = None
            if chat_room['sender'] == user_id:
                is_creator = True
                other_person = chat_room['receiver']
            elif chat_room['receiver'] == user_id:
                is_creator = False
                other_person = chat_room['sender']
                print('---------------- in elif')
            else:
                pass

            if is_creator is False and chat_room.get("offer_status") == "rejected":
                pass

            room_creation_date = parser.parse(chat_room['createdAt'])
            now_time = datetime.datetime.now()
            t = now_time - room_creation_date
            if t.days >= 2:
                print("Chatroom expired - {}".format(str(chat_room['_id'])))
                upd_chatroom = chat_room_obj.update_one({"_id":chat_room['_id']},{"$set":{"editor_response":False, "offer_status":"expired"}})
                chat_room = chat_room_obj.find_one({"_id":chat_room['_id']})

            print(other_person)
            try:
                other_person_data = user_obj.find_one({"_id":ObjectId(other_person)})
                print(other_person_data)
                full_name = other_person_data['firstName'] + ' ' + other_person_data['lastName']
                if search_text == "":
                    data.append({
                        "userId" : str(other_person_data['_id']),
                        "firstName" : other_person_data['firstName'],
                        "lastName" : other_person_data['lastName'],
                        "profile_picture" : other_person_data.get("profile_picture",""),
                        "lastSeen" : "to be implemented",
                        "firstChatDate" : chat_room.get("createdAt",""),
                        "lastMessage" : chat_room.get("lastMessage",""),
                        "unreadMessagesCount" : msg_obj.count_documents({"chat_room_id":str(chat_room['_id']), "isSeen":False, "receiver":user_id}),
                        "acquisitionStatus" : chat_room.get("acquisitionStatus", False),
                        "acquisitionTime" : chat_room.get("acquisitionTime",""),
                        "sort_date": chat_room.get("lastMessageTime","") if chat_room.get("lastMessageTime","") != "" else chat_room.get("createdAt",""),
                        "editor_response":chat_room.get('editor_response',None),
                        "editor_response_time":chat_room.get('editor_response_time',""),
                        "offer_status":chat_room.get('offer_status',""),
                        "chat_room_id":str(chat_room.get("_id","")),
                        "job_id":chat_room.get('job_id',""),
                        
                    })
                elif search_text.lower() in full_name.lower():
                    data.append({
                        "userId" : str(other_person_data['_id']),
                        "firstName" : other_person_data['firstName'],
                        "lastName" : other_person_data['lastName'],
                        "type" : other_person_data.get('type'),
                        "profilePicture" : other_person_data.get("profile_picture",""),
                            "lastSeen" : "to be implemented",
                        "firstChatDate" : chat_room.get("createdAt",""),
                        "lastMessage" : chat_room.get("lastMessage",""),
                        "unreadMessagesCount" : msg_obj.count_documents({"chat_room_id":str(chat_room['_id']), "isSeen":False, "receiver":user_id}),
                        "acquisitionStatus" : chat_room.get("acquisitionStatus",False),
                        "acquisitionTime" : chat_room.get("acquisitionTime",""),
                        "sort_date": chat_room.get("lastMessageTime","") if chat_room.get("lastMessageTime","") != "" else chat_room.get("createdAt",""),
                        "editor_response":chat_room.get('editor_response',None),
                        "editor_response_time":chat_room.get('editor_response_time',""),
                        "offer_status":chat_room.get('offer_status',""),
                        "chat_room_id":str(chat_room.get("_id","")),
                        "job_id":chat_room.get('job_id',""),
                    })
                else:
                    pass
            except:
                pass

        data = sorted(data, key=lambda d:d["sort_date"], reverse = True)
        response = jsonify(data)
        return response, 200
    

    
    @editors.route('/chat/conversations/<user_id>', methods=['GET']) # please send chatroom ID 
    # @token_required
    def fetchUserConversationsWithAnotherUser(user_id):
        msg_obj = mongo.db.messages
        chat_room_obj = mongo.db.chatroom
        req_param = request.args
        if 'chat_room_id' not in req_param:
            return jsonify({'message': "Please provide Chat Room ID"}), 400
        
        if 'with_user_id' not in req_param:
            return jsonify({'message': "Please provide with_user_id"}), 400
        
        
        ex1 = chat_room_obj.find_one({"_id":ObjectId(req_param['chat_room_id'])})
        if ex1 is None:
            return jsonify({'message': "Acquisition not sent"}), 400
        else:
            chat_room_id = ex1['_id']
            ex = ex1

        sender_receiver = sorted([ex['sender'], ex['receiver']])
        request_sender_receiver = sorted([user_id, req_param['with_user_id']])

        if sender_receiver != request_sender_receiver:
            return jsonify({'message': "There is some mismatch in chatroom and sender/receiver, please check request."}), 400
        
        #if ex['paymentStatus'] is not True:
        #    return jsonify({'message': "Payment is Pending."}), 400
        
        # if ex.get('acquisitionStatus', False) is not True:
        #     return jsonify({'message': "Aqcuisition is Pending."}), 400
        
        res = {}
        if chat_room_id:
            all_messages = msg_obj.find({"chat_room_id":str(chat_room_id)})
            data = []
            print()
            
            for message in all_messages:
                data.append({
                    "userId" : message.get("sender",""),
                    "toUserId" : message.get("receiver",""),
                    "date" : message.get("createdAt",""),
                    "message" : message.get("message",""),
                    "acquisitionStatus" : ex.get("acquisitionStatus",False),
                    "chat_room_id":str(ex.get("_id","")),
                })
                print(type(msg_obj))
                if message['receiver'] == user_id:
                    msg_obj.update_one({"_id":message['_id']}, {"$set":{"isSeen":True}})
        
            chat_room_obj.update_one({"_id":chat_room_id}, {"$set":{"isLastMessageSeen":True}})


        url = "https://stage-api.billionviews.ai/chat/conversations/{}?with_user_id={}".format(user_id, req_param["with_user_id"])
        start = req_param.get('start')
        limit = req_param.get('limit')
        data=sorted(data, key=lambda d:d["date"], reverse = True)

        if start and limit:
            data = get_paginated_list(data, url, start, limit)

            if data is False:
                response = jsonify({'data': [], 'message': "No Jobs found."})
                return response, 200
        else:
            data = data

        
        res['conversations'] = data

        response = jsonify(res)
        return response, 200
    

    @editors.route('/editor/<editor_id>/new-contacts', methods=['GET'])
    # @token_required
    def fetchEditorNewContactsByID(editor_id):
    
        data = []
        chat_room_obj = mongo.db.chatroom
        user_obj = mongo.db.users
        
        data_filter = {}
        
        rgx = re.compile('.*{}.*'.format(editor_id), re.IGNORECASE)
        data_filter['$or'] = [{"sender":rgx},{"receiver":rgx}]
        all_chat_rooms = chat_room_obj.find(data_filter)
        for chat_room in all_chat_rooms:
            other_person = None
            if chat_room['sender'] == editor_id:
                other_person = chat_room['receiver']
            elif chat_room['receiver'] == editor_id:
                other_person = chat_room['sender']
            
            other_person_data = user_obj.find_one({"_id":ObjectId(other_person)})

            room_creation_date = parser.parse(chat_room['createdAt'])
            now_time = datetime.datetime.now()
            t = now_time - room_creation_date
            if t.days >= 2:
                print("Chatroom expired - {}".format(str(chat_room['_id'])))
                upd_chatroom = chat_room_obj.update_one({"_id":chat_room['_id']},{"$set":{"editor_response":False, "offer_status":"expired"}})
                chat_room = chat_room_obj.find_one({"_id":chat_room['_id']})
            

            data.append({
                "id" : str(other_person_data["_id"]),
                "firstName" : other_person_data['firstName'],
                "lastName" : other_person_data['lastName'],
                "profilePicture" : other_person_data.get("profile_picture",""),
                "lastSeen" : "to be implemented",
                "type" : other_person_data.get("type",""),
                "acquisitionStatus" : chat_room.get("acquisitionStatus", False),
                "editor_response":chat_room.get('editor_response',None),
                "editor_response_time":chat_room.get('editor_response_time',""),
                "offer_status":chat_room.get('offer_status',""),
                "chat_room_id":str(chat_room.get("_id","")),
            })

        print(data)

        response = jsonify(data)
        return response, 200

    @editors.route('/webhook/clickup/task-updated', methods=['POST'])
    def clickTaskupdatedWebhook():
        req_body = request.get_json()
        if '_id' in req_body:
            del req_body["_id"]
        try:
            
            if req_body['event'] == 'taskUpdated':
                url = "https://api.clickup.com/api/v2/task/{}".format(req_body['task_id'])
                api_token = config('CLICKUP_API_TOKEN')
                headers =  {"Authorization":api_token}
                resp = requests.get(url=url, headers=headers)
                resp = json.loads(resp.text)
                applicants = mongo.db.applicants
                sub_task_id = req_body['task_id']
                print("+======================")
                print(resp['custom_fields'][6]['name'])
                if resp['custom_fields'][6]['name'] == 'Rating' and resp['custom_fields'][6]['value'] > 0:
                    application_obj = applicants.update_one({"clickup_sub_task_id":sub_task_id},{"$set":{"rating":resp['custom_fields'][6]['value'], "status":"active"}})
                else:
                    for custom_field in resp['custom_fields']:
                        if custom_field['name'] == "Rating":
                            if custom_field['value'] > 0:
                                application_obj = applicants.update_one({"clickup_sub_task_id":sub_task_id},{"$set":{"rating":custom_field['value'], "status":"active"}})
                

                logs = mongo.db.logs
                logs.insert_one(req_body)
                return jsonify({"message":"success"}), 200
        except Exception as e:
            logs = mongo.db.logs
            req_body['exception'] = str(e)
            logs.insert_one(req_body)
            return jsonify({"message":"falied"}), 200


    return editors

