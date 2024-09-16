import requests

# Clover API credentials and order details
access_token = "62ce1cda-5163-cc37-8c3d-514d920ac5ac"
merchant_id = "9N7D4W6ZBXGV1"
order_id = "WVRQ3NYWG7Z7R"
employee_id = "EP2ZB7ZXYQXHY"  # Employee ID from the order
tender_id = "E05BB2Q8VET3M"  # Cash tender ID

# The total amount to charge (sum of all item totals in cents)
total_amount = 3650  # Example total amount (sum from items added)

# API endpoint for processing payment
#url = f"https://sandbox.dev.clover.com/v3/merchants/{merchant_id}/payments"
url=f'https://sandbox.dev.clover.com/v3/merchants/{merchant_id}/orders/{order_id}/payments'

headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

# Payload for payment
payload = {
    "orderId": order_id,
    "amount": total_amount,  # Amount in cents
    "currency": "USD",
    "employee": {"id": employee_id},  # Employee ID
    "tender": {"id": tender_id}  # Cash tender ID
}

# Process the payment
response = requests.post(url, json=payload, headers=headers)

if response.status_code == 200:
    print("Payment processed successfully!")
    print(response.json())  # Optionally, print the payment details
else:
    print(f"Failed to process payment: {response.text}")
