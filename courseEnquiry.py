import json
import datetime
import time
import os
import re
import math
import random
import logging
import boto3

# dynamodb = boto3.resource('dynamodb')
# table = dynamodb.Table('instritutebot')

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def close(session_attributes, fulfillment_state, message):
    response = {
        'sessionAttributes': session_attributes,
        'dialogAction': {
            'type': 'Close',
            'fulfillmentState': fulfillment_state,
            'message': message
        }
    }
def elicit_intent(message):
    return {
        "dialogAction": {
            "type": "ElicitIntent",
            "message": {
                "contentType": "PlainText",
                "content": "This is javaHomeBot How can I help you today?"
                }
        }
    }
def elicit_slot(session_attributes, intent_name, slots, slot_to_elicit, message):
    return {
        'sessionAttributes': session_attributes,
        'dialogAction': {
            'type': 'ElicitSlot',
            'intentName': intent_name,
            'slots': slots,
            'slotToElicit': slot_to_elicit,
            'message': message,
        }
    }

def confirm_intent(session_attributes, intent_name, slots, message):
    logger.debug(message)
    return {
        'sessionAttributes': session_attributes,
        'dialogAction': {
            'type': 'ConfirmIntent',
            'intentName': intent_name,
            'slots': slots,
            'message': message
        }
    }

def delegate(session_attributes, slots):
    return{
        "sessionAttributes": session_attributes,
        "dialogAction": {
            "type": "Delegate",
            "slots": slots
        }
    }

def build_validation_result(is_valid, violated_slot, message_content):
    return {
        'isValid': is_valid,
        'violatedSlot': violated_slot,
        'message': {'contentType': 'PlainText', 'content': message_content}
    }
def validate_number(phone):
    if re.match(r"^[6-9]{1}\d{9}$", phone):
        return True
    else:
        return False

def validate_course_enquiry(Name, Phone, courseName):
    if not Name:
        return build_validation_result(False, 'Name', "may I know your name")
    elif not Phone:
        return build_validation_result(False, 'Phone', 'could you please provide phone number')
    elif Phone and not validate_number(Phone):
        return build_validation_result(False, 'Phone', 'This is not a valid number. could you please provide the valid phone number')
    elif not courseName:
        return build_validation_result(False, 'courseName', 'May I know which course are interested in ')
    return build_validation_result(True, None, None)
def greeting(intent_request):
    source = intent_request['invocationSource']
    if source == 'DialogCodeHook':
        return elicit_intent(
            None
        )

def course_enquiry(intent_request):
    Name = intent_request['currentIntent']['slots']['Name']
    Phone = intent_request['currentIntent']['slots']['Phone']
    courseName = intent_request['currentIntent']['slots']['courseName']
    source = intent_request['invocationSource']
    confirm_status = intent_request['currentIntent']['confirmationStatus']
    intent_name = intent_request['currentIntent']['name']
    try:
        data = {
            'Name': Name,
            'Phone': Phone,
            'courseName': courseName
            }
        intent_request['sessionAttributes']=data
    except Exception as e:
        logger.debug(e)

    output_session_attributes = intent_request['sessionAttributes'] if intent_request['sessionAttributes'] is not None else {}

    if source == 'DialogCodeHook':
        slots = intent_request['currentIntent']['slots']
        validation_result = validate_course_enquiry(Name, Phone, courseName)
        if not validation_result['isValid']:
            slots[validation_result['violatedSlot']] = None
            return elicit_slot(
                output_session_attributes,
                intent_name,
                slots,
                validation_result['violatedSlot'],
                validation_result['message']
            )
        if confirm_status == 'Denied':
            return delegate(
                output_session_attributes,
                slots
            )
        if confirm_status == 'None':
            return confirm_intent(
                output_session_attributes,
                intent_name,
                slots,
                None
            )
        if confirm_status == 'Confirmed':
            return delegate(
                output_session_attributes,
                slots
            )
    if source == 'FulfillmentCodeHook':
        return close(
        output_session_attributes,
        'Fulfilled',
        None
        )
def dispatch(intent_request):
    logger.debug('dispatch userId={}, intentName={}'.format(intent_request['userId'], intent_request['currentIntent']['name']))
    intent_name = intent_request['currentIntent']['name']
    if intent_name == "courceEnquiry":
        return course_enquiry(intent_request)
    if intent_name == "Greeting":
        return greeting(intent_request)
    raise Exception('Intent with name '+intent_name+'not supported')


def lambda_handler(event, context):
    logger.debug(event['bot']['name'])
    logger.debug(event)
    return dispatch(event)
