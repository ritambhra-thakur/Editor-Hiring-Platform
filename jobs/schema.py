from marshmallow import Schema, fields

class CreateJobSchema(Schema):
    title = fields.Str(required=True)
    details = fields.Dict(required=True)
    samples = fields.List(fields.Str(), required=False)

class UpdateJobSchema(Schema):
    title = fields.Str(required=True)
    details = fields.Dict(required=True)
    samples = fields.List(fields.Str(), required=False)