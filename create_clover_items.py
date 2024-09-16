import os
import requests
import postgresql_db_utils

# load environment variables
from config_loader import load_environment
load_environment()

# List of items to create
items = [
    {"name": "Latte", "price": 400, "sku": "sku_001"},
    {"name": "Espresso", "price": 300, "sku": "sku_002"},
    {"name": "Cappuccino", "price": 450, "sku": "sku_003"},
    {"name": "Mocha", "price": 500, "sku": "sku_004"},
    {"name": "Americano", "price": 350, "sku": "sku_005"},
    {"name": "Muffin", "price": 250, "sku": "sku_006"},
    {"name": "Croissant", "price": 300, "sku": "sku_007"},
    {"name": "Bagel", "price": 200, "sku": "sku_008"},
    {"name": "Sandwich", "price": 600, "sku": "sku_009"},
    {"name": "Smoothie", "price": 550, "sku": "sku_010"},
]

CLOVER_CREATE_ITEMS_URL = os.getenv('CLOVER_CREATE_ITEMS_URL')
CLOVER_MERCHANT_ID=os.getenv('CLOVER_MERCHANT_ID')

from clover_dal import CloverDAL
clover_dal = CloverDAL(postgresql_db_utils.get_connection())

# Function to create items in Clover
def create_items():
    url = CLOVER_CREATE_ITEMS_URL.format(MERCHANT_ID=CLOVER_MERCHANT_ID)
    print (f'----------url is {url}')
    access_token = clover_dal.get_token_by_merchant_id(CLOVER_MERCHANT_ID).get('access_token')
    if not access_token:
        raise ValueError(f'No access token available for merchant_id {CLOVER_MERCHANT_ID}')
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    for item in items:
        print (f'ci10------for item {item}')
        item_data = {
            "name": item['name'],
            "price": item['price'],
            "sku": item['sku'],
            "hidden": False  # set to False to make the item visible
        }
        print (f'------------------ci20------item_data {item_data}')
        
        # Make the API request to create the item
        response = requests.post(url, headers=headers, json=item_data)

        print (f'------------------ci30------response {response.status_code}')
        
        if response.status_code == 200:
            print (f'------------------ci40------')
            print(f"Item '{item['name']}' created successfully.")
        else:
            print (f'ci50------')
            print(f"Failed to create item '{item['name']}'. Status Code: {response.status_code}")
            print(response.json())
            status_code = response.status_code
            details = response.json()
            print (f'-----------error status_code: {status_code}')
            print (f'-----------error details: {details}')
            raise Exception(f"-----------------Failed to create item '{item['name']}' status code: {response.status_code}")
