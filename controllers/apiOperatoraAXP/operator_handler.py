import kopf
import kubernetes
import json
import requests
import logging
import sys
import base64
import time
from requests.exceptions import HTTPError

# Logging details are saving
log = logging.getLogger(__name__)
out_hdlr = logging.StreamHandler(sys.stdout)
out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
out_hdlr.setLevel(logging.DEBUG)
log.addHandler(out_hdlr)
log.setLevel(logging.DEBUG)

# Create consumer key and consumer secret key
# TODO: These will be removed
consumer_key = "6jCFjMAmCr01fLR7g9VSLFtI22sa"
consumer_secret = "VEGWmkl1Ro6J8oyjaUNiPRTILPwa"

# API Manager access token url
apim_token_url = "https://axp-dep-service:8243/token?grant_type=client_credentials&scope=apim:api_view " \
                 "apim:api_create apim:api_publish"
# API Create url
apim_api_create_url = "https://axp-dep-service:9443/api/am/publisher/v0.13/apis"

# API Publish url
apim_api_publish_url = "https://axp-dep-service:9443/api/am/publisher/v0.13/apis/change-lifecycle?apiId="

# Namespace name
name_space = "axp"

# Defining delay time
delay_time = 17

scopes_to_role_mapping = {'admin': 'role1,admin', 'regular': 'role2'}


# This method will be triggered when a ODA component is created in kubernetes cluster.
@kopf.on.create('oda.tmforum.org', 'v1alpha1', 'components')
def create_service(meta, spec, **kwargs):
    log.debug("ODA creation triggered")
    # Add delay since the service need to be deployed
    try:
        apis = spec['coreFunction']['exposedAPIs'] # expose APIs from ODA Component
        version = spec['version']
        for api in apis:
            api_name = api['name']
            api_path = api['path']
            api_implementation = api['implementation']
            api_scopes = api['scopes']
            port = api['port']
            log.debug(
                f'api_name: {api_name},api_path: {api_path},api_implementation: {api_implementation},port: {port}')
            create_api(api_name, api_path, str(port), api_implementation, version, api_scopes)

    except Exception as err:
        log.error(f'Other error occurred: {err}')

    return {'message': "service creation triggered"}


# WSO2 APIM token generation.
def token_generation():
    log.debug("Token generation started")
    token = "dump"
    try:
        header_key = encoder()
        headers = {'Authorization': header_key, 'Content-Type': 'application/x-www-form-urlencoded'}
        response = requests.post(apim_token_url, headers=headers, verify=False) # Create token using apim_token_url
        if response.status_code == 200:
            log.debug("Token creation success")
            response_body = response.json()
            token = response_body["access_token"]
        else:
            log.error(f'Invalid response code: {response.status_code}')
    except HTTPError as http_err:
        log.error(f'HTTP error occurred: {http_err}')
    except Exception as err:
        log.error(f'Other error occurred: {err}')

    return token


def encoder():
    key = consumer_key + ":" + consumer_secret
    key_bytes = key.encode('ascii')
    base64_bytes = base64.b64encode(key_bytes)
    base64_key = base64_bytes.decode('ascii')
    header_key = "Basic " + base64_key
    return header_key


# Create an api in WSO2 APIM
def create_api(service_name, path, port, implementation, version, api_scopes):
    log.debug("Api generation started")
    try:
        token = token_generation()  # Generate token
        token_bearer = "Bearer " + token
        swagger_url = 'http://' + service_name + path   # Swagger URL
        time.sleep(delay_time)  # wait until the microservice is crated and exposed as a service
        api_definition = get_swagger_definition(swagger_url, api_scopes)
        headers = {'Authorization': token_bearer, 'Content-Type': 'application/json'}
        log.debug(f"swagger: {swagger_url}")
        end_point_config = {
            'endpoint_type': 'http',
            'sandbox_endpoints': {'url': 'http://' + service_name + ':' + port},
            'production_endpoints': {'url': 'http://' + service_name + ':' + port},
        }
        # API Body parameters
        request_body = {
            'name': service_name,
            'description': implementation,
            'version': version,
            'provider': 'publisher1',
            'context': service_name,
            'apiDefinition': api_definition,
            'tiers': ['Bronze', 'Premium', 'Gold', 'Subscription', 'Unlimited', 'Default'],
            "transport": [
                'http',
                'https'
            ],
            'visibility': 'PUBLIC',
            'endpointConfig': json.dumps(end_point_config),
            'gatewayEnvironments': 'Production and Sandbox',
            "isDefaultVersion": False
        }
        ## API Creating response
        response = requests.post(apim_api_create_url, headers=headers, json=request_body, verify=False)
        # log.debug(
        #     f'apim_api_create_url: {apim_api_create_url},headers: {headers},request_body: {request_body}')
        log.debug(f"response: {response.content}")
        if response.status_code == 201:
            log.debug("Api creation success")
            response_body = response.json()
            application_id = response_body["id"]
            publish_api(application_id, token)
        else:
            log.error(f'Invalid response code: {response.status_code}')

    except HTTPError as http_err:
        log.error(f'HTTP error occurred: {http_err}')
    except Exception as err:
        log.error(f'Other error occurred: {err}')


# Publish an api in WSO2 APIM
def publish_api(id, auth_token):
    log.debug("Api publish started")
    try:
        headers = {'Authorization': "Bearer " + auth_token}
        url = apim_api_publish_url + id + "&action=Publish"
        response = requests.post(url, headers=headers, verify=False)
        if response.status_code == 200:
            log.debug("Api publish success")
    except HTTPError as http_err:
        log.error(f'HTTP error occurred: {http_err}')
    except Exception as err:
        log.error(f'Other error occurred: {err}')


# Get api definition
def get_swagger_definition(url, api_scopes):
    log.debug("Getting swagger details ")

    # Add scopes to the swagger details
    try:
        resp_body = {}
        scope_arry = []
        for scope in api_scopes:
            scope_name = scope['name']
            scope_obj = {
                'name': scope_name,
                'description': scope_name + ' privileges are available',
                'key': scope_name,
                'roles': scopes_to_role_mapping.get(scope_name)
            }
            scope_arry.append(scope_obj)
        scope_data = {
            'apim': {
                'x-wso2-scopes': scope_arry
            }
        }
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            resp_body = response.json()
            resp_body['x-wso2-security'] = scope_data
            log.debug("Swagger details gathered success")
        return json.dumps(resp_body)
    except HTTPError as http_err:
        log.error(f'HTTP error occurred: {http_err}')
    except Exception as err:
        log.error(f'Other error occurred: {err}')
