import boto3
from ..settings import AWS_ACCESS_KEY, AWS_SECRET_KEY

fs = boto3.resource(
    's3',
    endpoint_url='https://s3.ap-southeast-1.wasabisys.com',
    aws_access_key_id='AWS_ACCESS_KEY',
    aws_secret_access_key='AWS_SECRET_KEY'
)

bucket = fs.Bucket('bv-sample-videos')

bucket.upload_file('hello.txt', 'h.txt')