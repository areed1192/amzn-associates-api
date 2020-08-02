import json
import hmac
import requests

from datetime import datetime

from typing import List
from typing import Dict
from typing import Union
from typing import Optional


class AmazonAssociatesClient():

    def __init__(self, access_key: str, secret_key: str, partner_tag: str) -> None:
        """Initializes the `AmazonAssociatesClient` object.

        Overview:
        ----
        To use the Amazon Associates Marketing API, you'll need to sign up for a
        developer account and get a `access_key` and a `secret_key` that will be
        used to authenticate your session.Additionally, you'll need to provide 
        your Amazon Associates `partner_tag` to uniquely identify yourself with 
        the API.

        Resource Link:
        ----
        For more info, please go to this link and learn how to sign up.

        https://webservices.amazon.com/paapi5/documentation/register-for-pa-api.html

        Arguments:
        ----

        access_key (str): Your Amazon Marketing API access key.

        secret_key (str): Your Amazon Marketing API secret key.

        partner_tag (str): Your Amazon Associates partner tag ID.

        Usage:
        ----
        """        
        
        # Store the passed through arguments.
        self.access_key = access_key
        self.secret_key = secret_key
        self.partner_tag = partner_tag

        # Define components needed for oAuth
        self.host = 'webservices.amazon.com'
        self.region = 'us-east-1'
        self.algorithm = "AWS4-HMAC-SHA256"
        self.service = "ProductAdvertisingAPI"


    def get_amz_date(self, utc_timestamp):
        return utc_timestamp.strftime('%Y%m%dT%H%M%SZ')

    def update_params_for_auth(self, headers, querys, auth_settings, api_name, method, body, resource_path):
        """Updates header and query params based on authentication setting.

        :param headers: Header parameters dict to be updated.
        :param querys: Query parameters tuple list to be updated.
        :param auth_settings: Authentication setting identifiers list.
        """
        if not auth_settings:
            service = 'ProductAdvertisingAPI'
            utc_timestamp = datetime.datetime.utcnow()
            headers['x-amz-target'] = 'com.amazon.paapi5.v1.ProductAdvertisingAPIv1.' + api_name
            headers['content-encoding'] = 'amz-1.0'
            headers['Content-Type'] = 'application/json; charset=utf-8'
            headers['host'] = self.host
            headers['x-amz-date'] = self.get_amz_date(utc_timestamp)
            aws_v4_auth = AWSV4Auth(
                access_key=self.access_key,
                secret_key=self.secret_key,
                host=self.host,
                region=self.region,
                service=service,
                method_name=method,
                timestamp=utc_timestamp,
                headers=headers,
                payload=self.sanitize_for_serialization(body),
                path=resource_path
            )
            auth_headers = aws_v4_auth.get_headers()

    def _prep_header_auth(self, method: str, api_name: str):

        # Create the Scope.
        self.credential_scope = '/'.join([self.access_key, self.region, 'ProductAdvertisingAPI', 'aws4_request'])

        # Create the Signed Header.
        self.signed_header = ";".join(['content-encoding','host','x-amz-date','x-amz-target'])
                
        # Step 1: Prepare the URL.
        canonical_request = self.prepare_canonical_url()
        
        # Step 2: Sign the request.
        string_to_sign = self.prepare_string_to_sign(
            canonical_request=canonical_request
        )

        # Step 3: Grab the Key.
        signing_key = self.get_signature_key(
            self.secret_key, self.xAmzDate, self.region, self.service
        )

        # Step 4: Get the signature.
        signature = self.get_signature(
            signing_key=signing_key, string_to_sign=string_to_sign
        )

        # Prep the template.
        auth_header_temp = "Authorization: {algo} Credential={access_key} SignedHeaders={signed_header} Signature={signature}"

        # Fill out the Auth portion.
        auth_header_temp = auth_header_temp.format(
            algo=self.algorithm,
            access_key=self.access_key,
            signed_headers=self.signed_header,
            signature=signature
        )
        
        headers['x-amz-target'] = 'com.amazon.paapi5.v1.ProductAdvertisingAPIv1.' + api_name
        headers['content-encoding'] = 'amz-1.0'
        headers['Content-Type'] = 'application/json; charset=utf-8'
        headers['host'] = self.host
        headers['x-amz-date'] = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        headers['Authorization'] = auth_header_temp

        return headers

    def prepare_canonical_url(self, headers: dict):
        
        # Define the URI.
        canonical_uri = '{method}\n{path}'.format(
            method=method_name,
            path=path
        )

        canonical_querystring = ""
        canonical_header = ""

        signed_header = ""
        sorted_keys = sorted(self.headers, key=str.lower)

        for key in sorted_keys:

            self.signed_header = self.signed_header + key.lower() + ";"
            
            canonical_header = (
                canonical_header + key.lower() + ":" + self.headers[key] + "\n"
            )

        self.signed_header = self.signed_header[:-1]

        payload_hash = hashlib.sha256(
            json.dumps(self.payload).encode("utf-8")
        ).hexdigest()

        canonical_request = (
            canonical_uri
            + "\n"
            + canonical_querystring
            + "\n"
            + canonical_header
            + "\n"
            + self.signed_header
            + "\n"
            + payload_hash
        )

        return canonical_request

    def prepare_string_to_sign(self, canonical_request):

        # self.algorithm = "AWS4-HMAC-SHA256"
        # self.credential_scope = (
        #     self.xAmzDate
        #     + "/"
        #     + self.region
        #     + "/"
        #     + self.service
        #     + "/"
        #     + "aws4_request"
        # )

        string_to_sign = (
            self.algorithm
            + "\n"
            + self.xAmzDateTime
            + "\n"
            + self.credential_scope
            + "\n"
            + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        )
        
        return string_to_sign

    def sign(self, access_key: str, msg: str) -> hmac.HMAC:

        new_hmac = hmac.new(
            key=access_key, 
            msg=msg.encode("utf-8"),
            digestmod=hashlib.sha256
        ).digest()
        
        return 

    def get_signature_key(self, key: str, date_stamp: str, region_name: str, service_name: str):

        k_date = self.sign(access_key=("AWS4" + key).encode("utf-8"), msg=date_stamp)
        k_region = self.sign(access_key=k_date, msg=region_name)
        k_service = self.sign(access_key=k_region, msg=service_name)
        k_signing = self.sign(access_key=k_service, msg="aws4_request")

        return k_signing

    def get_signature(self, signing_key: str, string_to_sign: str):

        signature = hmac.new(
            signing_key,
            string_to_sign.encode("utf-8"), 
            hashlib.sha256
        ).hexdigest()

        return signature

    def _build_url(self, endpoint: str) -> str:
        pass

    def _build_headers(self, mode: str = 'json') -> dict:
        """Create the headers for a request.

        Overview:
        ----
        Returns a dictionary of default HTTP headers for calls to the API,
        in the headers we defined the Authorization and access token.

        Arguments:
        ----
        mode (str) -- Defines the content-type for the headers dictionary
            can be one the following: [`json`, `form`]. (default: `json`)
        
        Returns:
        ----
        (dict) -- Dictionary with the Access token and content-type
            if specified.
        """

        # Date and time stamp
        self.date_time_amzn = self.timestamp.strftime("%Y%m%dT%H%M%SZ")
        self.date_amzn = self.timestamp.strftime("%Y%m%d")

        # create the headers dictionary
        headers = {'Authorization': 'Bearer {token}'.format(token = self.state['access_token'])}

        if mode == 'json':
            headers['Content-Type'] = 'application/json'
        elif mode == 'form':
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

        return headers


    def _make_request(self, method: str, endpoint: str, mode: str = None, params: dict = None, data: dict = None, json: dict = None) -> Union[Dict, List, List[Dict]]:
        """Handles all the requests in the library.

        A central function used to handle all the requests made in the library,
        this function handles building the URL, defining Content-Type, passing
        through payloads, and handling any errors that may arise during the request.

        Arguments:
        ----
        method: The Request method, can be one of the
            following: ['get','post','put','delete','patch']
        
        endpoint: The endpoint the client is requesting.

        mode: The content-type mode, can be one of the following: ['form','json']
        
        params (dict): The URL params for the request.
        
        data (dict): A data payload for a request.

        json (dict): A json data payload for a request

        Returns:
        ----
        A Dictionary object containing the JSON values.            
        """

        # First Build the full URL.
        full_url = self._build_url(endpoint=endpoint)

        # Second, grab the headers.
        headers = self._build_headers(mode=mode)

        # Build a new Session, and make it a verified session.
        new_session = requests.Session()
        new_session.verify = True

        # Build and prepare a new Request.
        new_request = requests.Request(
            method=method.upper(),
            url=full_url,
            headers=headers,
            params=params,
            json=json
        ).prepare()

        # Send the request, and grab the response.
        new_response: requests.Response = new_session.send(
            request=new_request
        )

        # Close the session.
        new_session.close()

        # Check if the response is Okay.
        if new_response.ok:
            
            # Parse the JSON string.
            return new_response.json()

        else:
            pass
