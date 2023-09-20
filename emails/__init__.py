import boto3
from settings import AWS_ACCESS_KEY, AWS_SECRET_KEY

client = boto3.client(
    'ses',
    region_name='us-east-1',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY
)


def assemble_data(dest_emails):
    """
    Destination={
        'ToAddresses': ['recipient1@domain.com', 'recipient2@domain.com'],
    },
    Message={
        'Body': {
            'Text': {
                'Charset': 'UTF-8',
                'Data': 'email body string',
            },
        },
        'Subject': {
            'Charset': 'UTF-8',
            'Data': 'email subject string',
        },
    },
    Source='sender.email@domain.com',
    """

    dest_list = dest_emails
    msg_data = 'Please click the link below to confirm your account: \n'
    subj_data = 'Welcome to BillionViews!'
    dest = {
        'ToAddresses': dest_list,
    }
    msg = {
        'Body': {
            'Text': {
                'Charset': 'UTF-8',
                'Data': msg_data,
            },
        },
        'Subject': {
            'Charset': 'UTF-8',
            'Data': subj_data
        },
    }
    src = 'tech@billionviews.ai'

    return dest, msg, src

def send(emails):
    dest, msg, src = assemble_data(emails)
    client.send_email(Destination=dest, Message=msg, Source=src)

    