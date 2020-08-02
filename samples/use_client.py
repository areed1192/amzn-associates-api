from configparser import ConfigParser

from amzn_associates.client import AmazonAssociatesClient

# Initialize the parser.
config = ConfigParser()

# Read and get the file.
config.read('config/config.ini')
ACCESS_KEY = config.get('credentials', 'access_key')
SECRET_KEY = config.get('credentials', 'secret_key')
PARTNER_TAG = config.get('credentials', 'partner_tag')


azmn_client = AmazonAssociatesClient(
    access_key=ACCESS_KEY,
    secret_key=SECRET_KEY,
    partner_tag=PARTNER_TAG
)

print(azmn_client.prepare_canonical_url())