# from flask import Flask
# # from db import mongo
# from auth import auth as auth_bp
# # from jobs import jobs as jobs_bp
# from editors import editors as editors_bp
# from reviewers import reviewers as reviewers_bp
# # from .bookings import bookings as bookings_bp

# def create_app(config_object='settings'):
#     app = Flask(__name__)

#     app.config.from_object(config_object)
#     # mongo.init_app(app)

#     app.register_blueprint(auth_bp)
#     # app.register_blueprint(jobs_bp)
#     app.register_blueprint(editors_bp)
#     app.register_blueprint(reviewers_bp)
#     print('------------ init')

#     # return app

# # create_app('settings')