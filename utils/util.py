import jwt
from settings import SALT, AWS_ACCESS_KEY, AWS_SECRET_KEY
from random import *
from flask_mail import Message
from bson import ObjectId
import time
# from constants import codes, messages
from flask import render_template
import base64
import boto3, botocore
import ast
import json
# from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
# import Paginator
from math import ceil
import operator
from functools import reduce
import requests
from decouple import config
import datetime
# from django.db.models import Q

IMAGE_EXTENSIONS = ['png', 'jpg', 'jpeg', 'PNG']

def encrypt(message):
    str_enc = base64.b64encode(str(message).encode("ascii")).decode("ascii")

    return str_enc


def decrypt(encMessage):
    # decMessage = base64.b64decode(encMessage + '=' * (-len(encMessage) % 4)).decode("ascii")
    encMessage = encMessage + '=' * (-len(encMessage) % 4)
    decMessage = (base64.b64decode((encMessage.encode("ascii")))).decode("ascii")
    return decMessage


def humanize_date(dt):
    if ',' in dt:
        time_list =dt.split(',')
        days_str = time_list[0]
        hrs_str = time_list[1]
    else:
        days_str = None
        hrs_str = dt
    
    split_hrs = hrs_str.split(':')
    if int(split_hrs[0]) == 0:
        if split_hrs[1] == '0' or split_hrs[1] == '00':
            final_str = "1 minute"
        else:
            final_str = split_hrs[1]+ ' ' + 'minutes'
    else:
        if int(split_hrs[1]) == 0:
            final_str = split_hrs[0] + ' ' + 'hours'
        else:
            final_str = split_hrs[0] + ' ' + 'hours' + ', ' + split_hrs[1]+ ' ' + 'minutes'
    if days_str:
        print(len(days_str))
        print(days_str)
        final_str = days_str + ', ' + final_str
        final_str = final_str.replace("  "," ")
    
    return final_str

def calc_application_completion(applicant_obj):
    
    completion_percentage = 100

    projectFile = applicant_obj.get("projectFile")
    pastVideos = applicant_obj.get("pastVideos")
    sampleVideo = applicant_obj.get("sampleVideo")

    if not sampleVideo:
        completion_percentage = completion_percentage - 33.33
    
    if not pastVideos:
        completion_percentage = completion_percentage - 33.33

    if not projectFile:
        completion_percentage = completion_percentage - 33.33
    
    if completion_percentage < 1:
        completion_percentage = 0
    
    return completion_percentage
# bytes_encoded = str_original.encode('utf_16', 'strict')
# print(type(bytes_encoded))

# str_decoded = bytes_encoded.decode('utf_16', 'strict')

# key = b'RrArvp6GMUYe1q8sB7dUFRt97V43HJSUVMPnHdFmqRM='
# def encrypt(msg):
#     key = b'RrArvp6GMUYe1q8sB7dUFRt97V43HJSUVMPnHdFmqRM='
#     return Fernet(key).encrypt(msg.encode())

# def decrypt(msg):
#     key = b'RrArvp6GMUYe1q8sB7dUFRt97V43HJSUVMPnHdFmqRM='
#     return Fernet(key).decrypt(msg) 

def getID(token):
    decoded_token = jwt.decode(token, SALT, algorithms = 'HS256')
    # print(">>>>>>>>>>> {}".format(type(decoded_token)))
    return decoded_token

def generateOTP(mail, to_email, otp):
    msg = Message('Email Verification for BillionViewsAI',sender='gaurav22gautam@gmail.com', recipients=[to_email])

    msg.body = "Hi There, your One-Time Password for Email Verification: " + str(otp)
    print(mail)
    mail.send(msg)

    return True

def generateVerificationLink(mail, to_email, verification_link):
    msg = Message('Email Verification for BillionViewsAI',sender='gaurav22gautam@gmail.com', recipients=[to_email])
    msg.body = "Hi There, your Forget Password Verification Link: " + verification_link
    mail.send(msg)
    return True


def saveimageinS3(db,csv_file, path, id):
    UID = db.users.find_one({"_id": ObjectId(id)} , {"UID":1,"_id":0})['UID']
    filename = str(time.time())+"."+UID.split(".")[-1]
    savePath = filename + '.csv'
    bucket_name = "billionviews-bucket"
    # csv_buffer = StringIO()
    # df.to_csv(csv_buffer)

    # df.to_csv(savePath)
    acl="public-read"
    # return {'CSV': savePath}
    # s3_resource = boto3.resource('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    # s3_resource.Bucket(bucket_name).Acl().put(ACL='public-read')
    # s3_resource.Object(bucket_name, filename).put(Body=csv_buffer.getvalue())
    
    s3 = boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)
    # import io
    url = s3.upload_fileobj(
            csv_file,
            bucket_name,
            filename+".csv",
            ExtraArgs={
                "ACL": acl,
                "ContentType": "csv"
            }
        )
    # print(url)
    s3_location = "http://{}.s3.ap-south-1.amazonaws.com/".format(bucket_name)
    return {'CSV': s3_location+filename+".csv"}

def getFormImages(request):
    # print(request.files)
    request.files = request.files.to_dict(flat=False)
    if(len(request.files) == 0):
        return ''
    else:
        request.files = {key: value for key, value in request.files.items()}
        files = []
        for file in request.files[list(request.files.keys())[0]]:
            # if file.filename.split(".")[-1] in IMAGE_EXTENSIONS:
            files.append(file)
        return files
    
def saveImage(image):
    image= image
    image_name = "-".join((image.filename).split(" "))
    bucket_name = "billionviews-io"

    s3 = boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)
    acl="public-read"
    url = s3.upload_fileobj(
            image,
            bucket_name,
            image_name,
            ExtraArgs={
                "ACL": acl,
                "ContentType": image.content_type
            }
        )
    s3_location = "https://{}.s3.us-east-1.amazonaws.com/".format(bucket_name)
    return "{}{}".format(s3_location, image_name)



def get_paginated_list(results, url, start, limit):
    start = int(start)
    limit = int(limit)
    count = len(results)
    if count < start or limit < 0:
        return False
    # make response
    obj = {}
    obj['start'] = start
    obj['limit'] = limit
    obj['count'] = count
    # make URLs
    # make previous url
    if start == 1:
        obj['previous'] = ''
    else:
        start_copy = max(1, start - limit)
        limit_copy = start - 1
        if '?' in url:
            obj['previous'] = url + '&start=%d&limit=%d' % (start_copy, limit_copy)
        else:
            obj['previous'] = url + '?start=%d&limit=%d' % (start_copy, limit_copy)
    # make next url
    if start + limit > count:
        obj['next'] = ''
    else:
        start_copy = start + limit
        if '?' in url:
            obj['next'] = url + '&start=%d&limit=%d' % (start_copy, limit)
        else:
            obj['next'] = url + '?start=%d&limit=%d' % (start_copy, limit)
    # finally extract result according to bounds
    obj['results'] = results[(start - 1):(start - 1 + limit)]
    return obj


def create_clickup_task(job_obj):
    # "projectType": "recurring"
    reference_link_list = [x["url"] for x in job_obj.get("referenceVideos",[])]
    reference_videos=""
    for reference_link in reference_link_list:
        reference_videos+= '\n '+reference_link
    req_body = {
"name": job_obj.get("title"),
"description": """
Video Category : {}
Reference Video Links : {}
Sample Edit Requirements : {}-min sample,
Files for a sample Edit : {},
Instructions: {}
                            """.format(    job_obj.get("category","NA"), reference_videos, job_obj.get("duration","NA"), job_obj.get("sampleEdit")['filesLink'], job_obj.get("sampleEdit")['instructions']),
            "assignees": [],
            "tags": [],
            "status": "Open",
            # "priority": 3,
            "due_date": datetime.datetime.strptime(job_obj.get("deadline","2023-09-21"), "%Y-%m-%d").timestamp()*1000,
            "due_date_time": False,
            # "time_estimate": 8640000,
            "start_date": datetime.datetime.now().timestamp()*1000,
            "start_date_time": False,
            "notify_all": True,
            "parent": None,
            "links_to": None,
            "custom_fields": [
                {
                "id": "8abfd8d4-1d38-4e4e-8560-545aa06e9bcb", # Price per video
                "value": float(job_obj.get("budget",0))
                },
                {
                "id": "6d1462d3-44a4-4cd8-babc-275431e05490", # Recurring
                "value": True if job_obj.get("projectType") == "recurring" else False 
                }
            ]
            }
    api_token = config('CLICKUP_API_TOKEN')
    headers = {"Authorization":api_token}
    list_id = 901002528829
    url = "https://api.clickup.com/api/v2/list/{}/task".format(list_id)
    try:
        resp_obj = requests.post(url, json=req_body, headers=headers)
        return json.loads(resp_obj.text)['id']
    except Exception as e:
        print(str(e))
        print(resp_obj.text)
        return False

def create_clickup_subtask(application_obj, clickup_task_id):


    #updating task status to submissions
    api_token = config('CLICKUP_API_TOKEN')
    headers = {"Authorization":api_token}

    task_update_url = "https://api.clickup.com/api/v2/task/{}".format(clickup_task_id)
    task_update_body = {"status": "Submissions"}
    resp_obj = requests.put(task_update_url, json=task_update_body, headers=headers)




    past_videos=""
    for past_vid in application_obj.get("pastVideos",[]):
        past_videos+= '\n  '+past_vid
    video_links = ""
    for sample_vid in application_obj.get("sampleVideo",[]):
        video_links+= '\n  '+sample_vid
    project_files = ""
    for pro_file in application_obj.get("projectFile",[]):
        project_files+= '\n  '+pro_file


    submission_timestamp = datetime.datetime.strptime(application_obj.get("createdAt","2023-09-21").replace("T"," "), "%Y-%m-%d %H:%M:%S.%f").timestamp()*1000
    req_body = {
            "name": application_obj.get("editor_name"),
            "description": """
Submissions:
    Video Link:{}
    Project File:{} 

Past Videos:{}""".format(video_links, project_files, past_videos),
            "assignees": [],
            "tags": [],
            "status": "Open",
            # "priority": 3,
            "due_date": submission_timestamp,
            "due_date_time": False,
            # "time_estimate": 8640000,
            "start_date": submission_timestamp,
            "start_date_time": False,
            "notify_all": True,
            "parent": clickup_task_id,
            "links_to": None,
            "custom_fields": [
                {
                "id": "8ae21643-a7f9-4aec-8315-abd9137421f7", # Audio & Sound Design 
                "value": 0
                },
                {
                "id": "61be704d-f7bd-4965-9e1a-740a4e143422", # Caption (typos, format)
                "value": 0
                },
                {
                "id": "14999e0e-5e2c-4620-92e7-ef68dd3f96b2", # Cuts
                "value": 0
                },
                {
                "id": "c9795931-dcea-40e8-a9ad-214023e50c01", # Effects
                "value": 0
                },
                {
                "id": "78dbf1b7-c5fb-4f92-ae91-ade6e0435a39", # Other requirements
                "value": 0
                },
                {
                "id": "dd49ee9c-454d-4222-8157-8be5b4ca0727", # Rating
                "value": 0
                },
                {
                "id": "76aed94c-ae75-4fc8-85d4-f85448ad757d", # Transitions
                "value": 0
                }
            ]
            }

    
    list_id = 901002528829
    url = "https://api.clickup.com/api/v2/list/{}/task".format(list_id)
    try:
        resp_obj = requests.post(url, json=req_body, headers=headers)
        print(resp_obj.text)
        return json.loads(resp_obj.text)['id']
    except Exception as e:
        print("==================== in exception")
        print(e)
        return str(e)
    
def create_report_task(report_obj):
    
    req_body = {
            "name": "test report",
            "description": "",
            "assignees": [],
            "tags": [],
            "status": "to do",
            # "priority": 3,
            "due_date": datetime.datetime.now().timestamp()*1000,
            "due_date_time": False,
            # "time_estimate": 8640000,
            "start_date": datetime.datetime.now().timestamp()*1000,
            "start_date_time": False,
            "notify_all": True,
            "parent": None,
            "links_to": None,
            "custom_fields": []
            }
    api_token = config('CLICKUP_API_TOKEN')
    headers = {"Authorization":api_token}
    list_id = 900902317289
    url = "https://api.clickup.com/api/v2/list/{}/task".format(list_id)
    try:
        resp_obj = requests.post(url, json=req_body, headers=headers)
        return json.loads(resp_obj.text)['id']
    except Exception as e:
        print("====================================================")
        print(str(e))
        print(resp_obj.text)
        return False