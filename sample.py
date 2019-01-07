import logging
import json
import re
import boto3

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('CourseEnquiry')

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

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

def validate_number(mobile):
    if not re.match(r'^\d{10,13}$',mobile):
        return False
    else:
        return True

def close(session_attributes, fulfillment_state, message):
    response = {
        'sessionAttributes': session_attributes,
        'dialogAction': {
            'type': 'Close',
            'fulfillmentState': fulfillment_state,
            'message': message
        }
    }

    return response


def delegate(session_attributes, slots):
    return {
        'sessionAttributes': session_attributes,
        'dialogAction': {
            'type': 'Delegate',
            'slots': slots
        }
    }


def elicit_slot(session_attributes, intent_name, slots, slot_to_elicit, message, response_card):
    return {
        'sessionAttributes': session_attributes,
        'dialogAction': {
            'type': 'ElicitSlot',
            'intentName': intent_name,
            'slots': slots,
            'slotToElicit': slot_to_elicit,
            'message': message,
            'responseCard': response_card
        }
    }


def build_validation_result(is_valid, violated_slot, message_content):
    return {
        'isValid': is_valid,
        'violatedSlot': violated_slot,
        'message': {'contentType': 'PlainText', 'content': message_content}
    }


def validate_course_enquiry(name, phone, courses):
    if not name:
        return build_validation_result(False, 'Name',
                                       'I will help you with course details, What\'s your name?')
    elif not phone:
        return build_validation_result(False, 'Phone',
                                       'Whats\'s your phone number?')
    elif phone and not validate_number(phone):
        return build_validation_result(False, 'Phone',
                                       f'Phone number, {phone} is invalid , please enter valid phone number.')
    elif not courses:
        return build_validation_result(False, 'CourseName',
                                       'Which course you are looking for?')
    return build_validation_result(True, None, None)


def make_enquiry(intent_request):
    name = intent_request['currentIntent']['slots']['Name']
    phone = intent_request['currentIntent']['slots']['Phone']
    courses = intent_request['currentIntent']['slots']['CourseName']
    source = intent_request['invocationSource']
    confirmation_status = intent_request['currentIntent']['confirmationStatus']
    # Set slots to sessionAttributes
    intent_name = [intent_request['currentIntent']['name']]
    logger.debug('AAaaaaaaaa')
    logger.debug(type(intent_request['sessionAttributes']))
    try:
        data = {
            'EnquiryType': 'Institute',
            'Name': name,
            'Phone': phone,
            'CourseName': courses
        }
        intent_request['sessionAttributes'] = data
    except Exception as e:
        logger.debug('In catch block')
        logger.debug(e)

    # logger.debug(intent_request['sessionAttributes'][intent_name])
    output_session_attributes = intent_request['sessionAttributes'] if intent_request[
                                                                           'sessionAttributes'] is not None else {}
    # booking_map = json.loads(try_ex(lambda: output_session_attributes['bookingMap']) or '{}')
    # perform validations
    if source == 'DialogCodeHook':
        slots = intent_request['currentIntent']['slots']
        validation_result = validate_course_enquiry(name, phone, courses)
        if not validation_result['isValid']:
            slots[validation_result['violatedSlot']] = None
            return elicit_slot(
                output_session_attributes,
                intent_request['currentIntent']['name'],
                slots,
                validation_result['violatedSlot'],
                validation_result['message'],
                None
            )
        logger.debug(json.dumps(intent_request))
        if confirmation_status == 'Denied':
            return delegate(output_session_attributes, slots)
        if confirmation_status == 'None':
            return confirm_intent(
                output_session_attributes,
                intent_request['currentIntent']['name'],
                slots,
                None
                )
        if confirmation_status == 'Confirmed':
            return delegate(output_session_attributes, slots)

    # Store Data to backend
    table.put_item(Item={
        'phone':phone,
        'name':name,
        'courses':courses
    })
    # output_session_attributes = {'CourseName':courses}
    return close(
        output_session_attributes,
        'Fulfilled',
        None

    )


def dispatch(intent_request):
    intent_name = intent_request['currentIntent']['name']
    # Dispatch to your bot's intent handlers
    if intent_name == 'CourseEnquiry':
        return make_enquiry(intent_request)
    raise Exception('Intent with name ' + intent_name + ' not supported')


def lambda_handler(event, context):
    logger.debug(event)
    resp = dispatch(event)
    logger.debug(json.dumps(resp))
    return resp
event = {
  'messageVersion': '1.0',
  'invocationSource': 'DialogCodeHook',
  'userId': 'j98qazmlk7rh2hh8fd6g4ewp1av5nmv7',
  'sessionAttributes': {
    'courseName': 'AWS',
    'Phone': '9999999999',
    'Name': 'Basker'
  },
  'requestAttributes': None,
  'bot': {
    'name': 'Institutebot',
    'alias': '$LATEST',
    'version': '$LATEST'
  },
  'outputDialogMode': 'Text',
  'currentIntent': {
    'name': 'courseEnquiry',
    'slots': {
      'courseName': 'AWS',
      'Phone': '9999999999',
      'Name': 'Basker'
    },
    'slotDetails': {
      'courseName': {
        'resolutions': [
          {
            'value': 'AWS'
          }
        ],
        'originalValue': 'AWS'
      },
      'Phone': {
        'resolutions': [

        ],
        'originalValue': '9999999999'
      },
      'Name': {
        'resolutions': [

        ],
        'originalValue': 'Basker'
      }
    },
    'confirmationStatus': 'Confirmed'
  },
  'inputTranscript': 'i am looking for course'
}
lambda_handler(event, "")
