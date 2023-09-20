from flask import Flask, render_template, session, request, \
    copy_current_request_context
#from db import mongo
from auth import auth_bp
from flask_mail import Mail
# from jobs import jobs as jobs_bp
from editors import editors_bp
from creator import reviewers_bp
from common import common_bp
from payment import payments_bp
from flask_cors import CORS
from flask_pymongo import PyMongo
from settings import *
# from .bookings import bookings as bookings_bp

from threading import Lock
from flask_socketio import SocketIO, emit, join_room, leave_room, \
    close_room, rooms, disconnect


app = Flask(__name__)
app.secret_key = SALT
app.config.from_object('settings')
app.config["MONGO_URI"] = "mongodb://localhost:27017/billionViews"
cors = CORS(app, resources={r"/*": {"origins": "*"}})
app.config['CORS-HEADERS'] = 'Content-Type'
mongo = PyMongo(app)

app.config["MAIL_SERVER"]='smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = 'gaurav22gautam@gmail.com'
app.config['MAIL_PASSWORD'] = 'diyshvckbussciml'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)


app.register_blueprint(auth_bp(mongo, mail))
app.register_blueprint(editors_bp(mongo, mail))
app.register_blueprint(reviewers_bp(mongo, mail))
app.register_blueprint(common_bp(mongo, mail))
app.register_blueprint(payments_bp(mongo, mail))


async_mode = None
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=async_mode)
socketio.init_app(app, cors_allowed_origins="*")
thread = None
thread_lock = Lock()

def background_thread():
    count = 0
    while True:
        socketio.sleep(10)
        count += 1
        socketio.emit('my_response',
                    {'data': 'Server generated event', 'count': count},
                    namespace='/test')

@app.route('/')
def index():
    return render_template('index.html', async_mode=socketio.async_mode)


@socketio.on('my_event', namespace='/test')
def test_message(message):
    print("=======================")
    print(message['data'])
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
        {'data': message['data'], 'count': session['receive_count']})


@socketio.on('my_broadcast_event', namespace='/test')
def test_broadcast_message(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
        {'data': message['data'], 'count': session['receive_count']},
        broadcast=True)


@socketio.on('join', namespace='/test')
def join(message):
    join_room(message['room'])
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
        {'data': 'In rooms: ' + ', '.join(rooms()),
        'count': session['receive_count']})


@socketio.on('leave', namespace='/test')
def leave(message):
    leave_room(message['room'])
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
        {'data': 'In rooms: ' + ', '.join(rooms()),
        'count': session['receive_count']})


@socketio.on('close_room', namespace='/test')
def close(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response', {'data': 'Room ' + message['room'] + ' is closing.',
                        'count': session['receive_count']},
        room=message['room'])
    close_room(message['room'])


@socketio.on('my_room_event', namespace='/test')
def send_room_message(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
        {'data': message['data'], 'count': session['receive_count']},
        room=message['room'])


@socketio.on('disconnect_request', namespace='/test')
def disconnect_request():
    @copy_current_request_context
    def can_disconnect():
        disconnect()

    session['receive_count'] = session.get('receive_count', 0) + 1
    # for this emit we use a callback function
    # when the callback function is invoked we know that the message has been
    # received and it is safe to disconnect
    emit('my_response',
        {'data': 'Disconnected!', 'count': session['receive_count']},
        callback=can_disconnect)


@socketio.on('my_ping', namespace='/test')
def ping_pong():
    emit('my_pong')


@socketio.on('connect', namespace='/test')
def test_connect():
    global thread
    with thread_lock:
        if thread is None:
            thread = socketio.start_background_task(background_thread)
    emit('my_response', {'data': 'Connected', 'count': 0})


@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected', request.sid)


socketio.run(app, debug=True)



