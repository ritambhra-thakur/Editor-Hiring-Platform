from marshmallow import Schema, fields

class LoginSchema(Schema):
    email = fields.Str(required=True)
    password = fields.Str(required=True)

class RegisterSchema(Schema):
    email = fields.Str(required=True)
    password = fields.Str(required=True)
    firstName = fields.Str(required=True)
    lastName = fields.Str(required=True)
    type = fields.Str(required=True)
    profilePictrue = fields.Str(required=False)
    accessToken = fields.Str(required=False)
    contacts = fields.Str(required=False)
    bio = fields.Str(required=False)
    emailVerified = bool()
