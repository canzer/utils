from flask import session, jsonify
import json, os, time, requests, urllib.parse
from datetime import datetime, timedelta
import pytz


#timezone settings
eastern = pytz.timezone('America/New_York')


##############SAML RELATED PYTHON3-SAML##############################

# Load SAML settings
def get_saml_settings():
    try:
        # Get the absolute directory of this script
        base_path = os.path.dirname(os.path.abspath(__file__))

        # Construct the absolute path to the 'saml/settings.json' file
        settings_path = os.path.join(base_path, 'saml\saml_settings')
        
        #print(f"Attempting to locate SAML settings from: {settings_path}")

        return settings_path
        
    except FileNotFoundError:
        print("Error: settings.json file not found.")
        raise
    except json.JSONDecodeError:
        print("Error: settings.json file is not a valid JSON.")
        raise

#Prepare/format SAML response for python3-saml functions

def prepare_flask_request(request):
    # Determine the port, defaulting to 5000 if not found
    server_port = request.environ.get('SERVER_PORT', '5000') if request.environ.get('wsgi.url_scheme') == 'http' else '443'
    
    return {
        'http_host': request.host,
        'server_port': server_port,
        'script_name': request.script_root,
        'path_info': request.path,
        'query_string': request.query_string,
        'http_user_agent': request.user_agent.string,
        'http_accept': request.accept_mimetypes,
        'http_referer': request.referrer,
        'http_method': request.method,
        'post_data': request.form if request.method == 'POST' else None,
    }


#Extract SAML User attributes

def extract_user_attributes():
    """
    Extracts user attributes from session['user'].
    
    Returns:
        A dictionary of user attributes where the first value in each attribute's list is stored.
        If the session['user'] is empty or doesn't exist, an empty dictionary is returned.
    """
    user_data = session.get('user', {})
    
    # Create a dictionary to store the extracted key-value pairs
    extracted_user_data = {}
    
    # Loop through the user data dictionary and extract the first value from each list
    for key, value in user_data.items():
        if value:  # Ensure the value list is not empty
            extracted_user_data[key] = value[0]  # Store the first value
    
    return extracted_user_data


##############SAML RELATED PYTHON3-SAML##############################










####################ONELOGIN TOKEN GENERATION LOGIC###########################




# Store the client credentials in environment variables or securely in your code
ONELOGIN_CLIENT_ID = "#" #os.getenv('ONELOGIN_CLIENT_ID') 
ONELOGIN_CLIENT_SECRET = "#" #os.getenv('ONELOGIN_CLIENT_SECRET')

BASE_URL_V2 = "https://#.com/api/2/"
BASE_URL_V1 = "https://#.com/api/1/"

# Token expiration time (OneLogin tokens expire after a certain period)
TOKEN_EXPIRATION_TIME = 3600  # Usually 1 hour (in seconds)

# You can use a file, environment variable, or database to store the token
TOKEN_FILE = 'onelogin_token.txt'

#How many hours we look for OneLogin user events
event_hours_lookup = 1

# List of HTTP status of HTTP/API calls, used for matching logic in various functions
success_codes = [200, 201, 202]
client_error_codes = [400, 401, 403, 404]
server_error_codes = [500, 502, 503]


def get_token():
    """
    Function to retrieve a API token.
    It checks if a valid token exists; if not, it generates a new one.
    Returns:
        str: The valid API token.
    """
    # Check if a token already exists and is valid
    token_data = load_token()
    if token_data and not is_token_expired(token_data):
        print("Reusing token, not expired.")
        #print(token_data['access_token'])
        return token_data['access_token']

    # Generate a new token if the existing one is expired or doesn't exist
    url = 'https://#.com/auth/oauth2/v2/token'  # Adjust for your region (US/EU)
    headers = {
        'Authorization': f'client_id:{ONELOGIN_CLIENT_ID}, client_secret:{ONELOGIN_CLIENT_SECRET}',
        'Content-Type': 'application/json'
    }
    body = {
        'grant_type': 'client_credentials'
    }

    response = requests.post(url, json=body, headers=headers)
    if response.status_code == 200:
        token_data = response.json()
        token_data['expires_at'] = time.time() + TOKEN_EXPIRATION_TIME
        save_token(token_data)
        return token_data['access_token']
    else:
        raise Exception(f"Error fetching token: {response.status_code} - {response.text}")


def is_token_expired(token_data):
    """
    Check if the token is expired based on the stored expiration time.
    Args:
        token_data (dict): The token data containing the access token and expiration time.
    Returns:
        bool: True if token is expired, False otherwise.
    """
    return time.time() > token_data['expires_at']


def load_token():
    """
    Load the token from a file or secure storage.
    Returns:
        dict: Token data if it exists, None if it doesn't.
    """
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as f:
            return eval(f.read())  # Use eval here cautiously. Consider using json for safety.
    return None


def save_token(token_data):
    """
    Save the token to a file or secure storage.
    Args:
        token_data (dict): The token data to be saved.
    """
    print('Saving Token')
    with open(TOKEN_FILE, 'w') as f:
        f.write(str(token_data))


####################ONELOGIN TOKEN GENERATION LOGIC###########################







####################ONELOGIN API CALLS######################################

def get_user_data(username):

    # Set the API endpoint for querying a specific user by username
    url = f"{BASE_URL_V2}users?email={username}"  # Assuming email is used as username

    #Obtain API access token prior to API call
    access_token = get_token()
    
    # Set the headers including the access token
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    try:
        # Make the GET request to the OneLogin API
        response = requests.get(url, headers=headers)

        #response variables
        response_code = response.status_code
        response_text = response.text

        #sleep for testing, can be removed
        #time.sleep(1)

        # Check the status code
        if response_code in success_codes:
            #Success
            #Loads API response
            user_data = response.json()
            print(user_data)

            #OneLogin route relies on this statically defined value in order to render proper template
            if not user_data:
                print({'userFound': 'false', 'message': f'Unable to find user - {username}'})
                return jsonify({'userFound': 'false', 'message': f'Unable to find user - {username}'}), 200

            #append status to list so ALPINE logic understands it was a success
            user_data[0]['userFound'] = 'True'
            
            return user_data
        
        elif response_code in client_error_codes:
            #Client issue, 400 errors like unauthorized
            print(f"Error: {response_code} - {response_text}")
            return "Client error!"
        

        elif response_code in server_error_codes:
            #Endpoint error, whats up with this vendor?
            return "Server error!"
        

        else:
            #Undefined error codes, manual intervention on how to handle/adapt
            print(f"Error: {response_code} - {response_text}")
            return f"Error: {response_code} - {response_text}"


    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    

def get_user_enrolled_factors(user_id):

    """Get a user's enrolled factors"""
    url = f"{BASE_URL_V2}mfa/users/{user_id}/devices"

    access_token = get_token()

    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print(response.json())
        return response.json()
    else:
        response.raise_for_status()

def trigger_default_factor(user_id):
    """Trigger the default enrolled factor for a user."""
    factors = get_user_enrolled_factors(user_id)

    # Determine the default factor
    default_factor = next((factor for factor in factors if factor['default']), None)
    
    if not default_factor:
        print("No default factor found.")
        return("No default factor found.")

    # Trigger the default factor
    factor_id = default_factor['device_id']

    #print(factor_id)

    access_token = get_token()

    url = f"{BASE_URL_V2}mfa/users/{user_id}/verifications"
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    payload = {
        'device_id': f'{factor_id}'
    }
    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()  # Raise an error for bad responses

    if response.status_code == 201:
        print("2FA trigger worked.")
        return("Successfully triggered default factor.")
    else:
        return("Error Occurred.")



def get_user_events(user_id):
    """Pull user events for a specific user."""

    ##format time for query parameter
    # Get the current time
    current_time = datetime.utcnow()  # Get the current UTC time
    # Add one hour
    future_time = current_time - timedelta(hours=event_hours_lookup)
    # Format the future time in the desired format
    formatted_time = future_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    until_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    
    
    access_token = get_token()

    if not access_token:
        return None

    url = f"{BASE_URL_V1}events?user_id={user_id}&since={formatted_time}&until={until_time}&limit=25"
    #print(url)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    response = requests.get(url, headers=headers)
    response_code = response.status_code
    response_text = response.text

    if response_code in success_codes:
        events = response.json()['data']
        #print(events)
        return events

    elif response_code in client_error_codes:
        #Client issue, 400 errors like unauthorized
        print(f"Error: {response_code} - {response_text} (get_user_events function)")
        return(f"Error: {response_code} - {response_text} (get_user_events function)")

    elif response_code in server_error_codes:
        print(f"Error: {response_code} - {response_text} (get_user_events function)")
        return(f"Error: {response_code} - {response_text} (get_user_events function)")
    
    else:
        #Undefined error codes, manual intervention on how to handle/adapt
        print(f"Error: {response_code} - {response_text} (get_user_events function)")
        return f"Error: {response_code} - {response_text} (get_user_events function)"      


def get_onelogin_event_types():
    """Get event ID and their types"""

    access_token = get_token()
    if not access_token:
        return None

    url = f"{BASE_URL_V1}events/types"
    #print(url)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        
        eventtypes = response.json()['data']
        
        # Check if the file already exists
        if os.path.exists('onelogin_event_types.json'):
            print("File 'onelogin_event_types.json' already exists. Not overwriting.")
        else:
            with open('onelogin_event_types.json', 'w') as json_file:
                json.dump(eventtypes, json_file, indent=4)  # Write the response to the file
                print("Data successfully saved to onelogin_event_types.json")
        
    else:
        print(f"Error retrieving event ID types: {response.status_code} {response.text}")
        return None



def update_user_api(user_id, value):

    access_token = get_token()

    if not access_token:
        return None

    url = f"{BASE_URL_V2}users/{user_id}"
    #print(url)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    payload = {
        'title': f'{value}'
    }
    response = requests.put(url, json=payload, headers=headers)

    response_code = response.status_code
    response_text = response.text

    if response_code in success_codes:
        updated_value = response.json()['data']
        #print(events)
        return updated_value

    elif response_code in client_error_codes:
        #Client issue, 400 errors like unauthorized
        print(f"Error: {response_code} - {response_text} (get_user_events function)")
        return(f"Error: {response_code} - {response_text} (get_user_events function)")

    elif response_code in server_error_codes:
        print(f"Error: {response_code} - {response_text} (get_user_events function)")
        return(f"Error: {response_code} - {response_text} (get_user_events function)")
    
    else:
        #Undefined error codes, manual intervention on how to handle/adapt
        print(f"Error: {response_code} - {response_text} (get_user_events function)")
        return f"Error: {response_code} - {response_text} (get_user_events function)"      

####################ONELOGIN API CALLS######################################



def format_onelogin_events(userevents):

    formatted_list = []

    #Load static file, should generate on website load via "get_onelogin_event_types"
    with open('onelogin_event_types.json', 'r') as file:
        OL_EventFile = json.load(file)
        #print(userevents)

    eventcount = len(userevents)
    print(f"Found {eventcount} events")

    if not userevents:
        print("Unable to retrieve events")
    else:
        #Loop on each event and determine variables
        for event_details in userevents:
            event_id = event_details['event_type_id']
            event_username = event_details['user_name']
            event_time = event_details['created_at']
            event_actoruser = event_details['actor_user_name']
            event_rolename = event_details['role_name']
                                        
            #format event time
            event_time_formatted = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            event_time_formatted = event_time_formatted.astimezone(eastern)
            event_time_formatted = event_time_formatted.strftime('%m-%d-%Y %I:%M:%S %p')
            #print(event_time_formatted)

            if event_details['app_name']:
                event_appname = event_details['app_name']
            
            #Loop on static file to match event_type_id to id (event) and format description
            for event_type in OL_EventFile:
                OL_event_ID = event_type['id']
                OL_event_description = event_type['description']

                if event_id == OL_event_ID:

                    if not OL_event_description:
                        description = f"Event Description is NULL - Event Type ID: {OL_event_ID}"
                    elif '%user' and '%app%' in OL_event_description:
                        description = OL_event_description.replace("%user%", event_username).replace("%app%", event_appname)
                    elif '%actor_user%' and '%user%' in OL_event_description:
                        description = OL_event_description.replace("%actor_user%", event_actoruser).replace("%user%", event_username)
                    elif '%user%' and '%role%' in OL_event_description:
                        description = OL_event_description.replace("%user%", event_username).replace("%role%", event_rolename)
                    elif '%user%' in OL_event_description:
                        description = OL_event_description.replace("%user%", event_username)
                    else:
                        description = OL_event_description
                    #print(description)

                    #append to new list to return for front end rendering
                    formatted_event = {
                        "event_id": OL_event_ID,
                        "description": description,
                        "time": event_time_formatted
                    }

                    formatted_list.append(formatted_event)
    
    if len(formatted_list) > 0:
        #sort events by time
        sorted_events = sorted(formatted_list, key=lambda x: x['time'], reverse=True)
        return(sorted_events)
    else:
        return None

