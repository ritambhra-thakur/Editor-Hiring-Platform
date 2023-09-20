import os

import stripe
from functools import wraps
from flask import jsonify, render_template, request, Blueprint
import jwt
from settings import SALT
# from utils.util import getID, generateOTP, generateVerificationLink, encrypt, decrypt, get_paginated_list
from decouple import config
from bson import ObjectId
import datetime
import ast
SECRET_KEY = SALT


stripe_keys = {
    "secret_key": config('stripe_secret_key'),
    "publishable_key": config('stripe_publishable_key'),
    "endpoint_secret": config('stripe_endpoint_secret'),
}

BE_DOMAIN = config('BE_DOMAIN') 
stripe.api_key = stripe_keys["secret_key"]

def payments_bp(mongo, mail):
    payments = Blueprint('payments', __name__)

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
    
    
    @payments.route("/hello")
    def hello_world():
        return jsonify("hello, world!")

    @payments.route("/stripe")
    def index():
        return render_template("index_stripe.html")

    @payments.route("/config")
    def get_publishable_key():
        stripe_config = {"publicKey": stripe_keys["publishable_key"]}
        return jsonify(stripe_config)
    
    @payments.route("/list-all-products")
    def list_all_products():
        res = stripe.Product.list()
        return jsonify(res)

    @payments.route("/create-checkout-session")
    def create_checkout_session():
        domain_url = BE_DOMAIN
        req_param = request.args
        if 'user_id' in req_param and 'product_id' in req_param:
            user_id = req_param['user_id']
            product_id = req_param['product_id']
            # if 'amount' in req_param:
            #     if str(req_param['amount']) == "10":
            #         token_acquired = 2

            #     elif str(req_param['amount']) == "20":
            #         token_acquired = 5
                
            #     elif str(req_param['amount']) == "50":
            #         token_acquired = 10
                
            #     elif str(req_param['amount']) == "50":
            #         token_acquired = 10
            try:
                res = stripe.Product.retrieve(product_id)
                res['default_price'] = stripe.Price.retrieve(res['default_price'])
            except Exception as e:
                return jsonify({"data":str(e), "message":"Problem while fetching product/Price"}), 400
            
            
            try:
                prod_description = ast.literal_eval(res['description'])
                tokens = prod_description['token']
            except Exception as ex:
                return jsonify({"data":str(ex), "message":"Problem while fetching product/Price"}), 400



            stripe.api_key = stripe_keys["secret_key"]
            try:
                # Create new Checkout Session for the order
                # Other optional params include:
                # [billing_address_collection] - to display billing address details on the page
                # [customer] - if you have an existing Stripe Customer ID
                # [payment_intent_data] - capture the payment later
                # [customer_email] - prefill the email input in the form
                # For full details see https://stripe.com/docs/api/checkout/sessions/create

                # ?session_id={CHECKOUT_SESSION_ID} means the redirect will have the session ID set as a query param
                checkout_session = stripe.checkout.Session.create(
                    client_reference_id="{}-{}".format(user_id,str(tokens)),
                    success_url=domain_url + "checkout/success",
                    cancel_url=domain_url + "checkout/cancel",
                    payment_method_types=["card"],
                    mode="payment",
                    line_items=[
                        {
                            "name": res['name'],
                            "quantity": 1,
                            "currency": "usd",
                            "amount": res['default_price']["unit_amount"],
                        }
                    ]
                )
                return jsonify({"sessionId": checkout_session["id"]})
            except Exception as e:
                return jsonify(error=str(e)), 403
        else:
            return jsonify({"message":"Please send all required fields"}), 400

    @payments.route("/success")
    def success():
        return render_template("success.html")


    @payments.route("/cancelled")
    def cancelled():
        return render_template("cancelled.html")


    @payments.route("/webhook", methods=["POST"])
    def stripe_webhook():

        payload = request.get_data(as_text=True)
        sig_header = request.headers.get("Stripe-Signature")

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, stripe_keys["endpoint_secret"]
            )

        except ValueError as e:
            # Invalid payload
            return "Invalid payload", 400
        except stripe.error.SignatureVerificationError as e:
            # Invalid signature
            return str(e), 400

        # Handle the checkout.session.completed event
        if event["type"] == "checkout.session.completed":
            print(event)
            extra_args = event['data']['object']['client_reference_id'].split('-')
            try:
                tran_obj = mongo.db.transactions
                inp_data = {
                    "user_id":extra_args[0],
                    "payment_body":event,
                    "symbol":"+",
                    "createdAt" : datetime.datetime.now().isoformat(),
                    "tokensAcquired":extra_args[1],
                    "description":"Payment Successful"
                }
                tran_obj.insert_one(inp_data)

                usr = mongo.db.users

                user_obj = usr.find_one({"_id": ObjectId(extra_args[0])})
                if 'tokensAcquired' in user_obj:
                    upd_obj = {"tokensAcquired":int(user_obj['tokensAcquired'])+int(extra_args[1])}
                else:
                    upd_obj = {"tokensAcquired":int(extra_args[1])}
            
                usr.update_one({"_id":ObjectId(extra_args[0])},{"$set":upd_obj})

            except Exception as e:
                
                failed_tran_obj = mongo.db.failed_transactions
                inp_data = {
                    "user_id":extra_args[0],
                    "payment_body":event,
                    "symbol":"+",
                    "createdAt" : datetime.datetime.now().isoformat(),
                    "tokensAcquired":extra_args[1],
                    "exception":str(e),
                    "description":"Error Encountered"
                }
                failed_tran_obj.insert_one(inp_data)

        return "Success", 200
    


    @payments.route('/creator/<creator_id>/transactions', methods=['GET'])
    # @token_required
    def fetchTokenCount(creator_id):
        tran_obj = mongo.db.transactions
        all_transactions = tran_obj.find({"user_id":creator_id})
        res = []
        for tran in all_transactions:
            del tran['_id']
            res.append(tran)
        return jsonify({"data":res,"message":"Transactions fetched successfully."}), 200
    return payments
