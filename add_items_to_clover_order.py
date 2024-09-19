import requests

# Clover API credentials and order details
access_token = "62ce1cda-5163-cc37-8c3d-514d920ac5ac"
merchant_id = "9N7D4W6ZBXGV1"
#order_id = "WVRQ3NYWG7Z7R"
#order_id = "W94SD2QJ19RJJ"
order_id = "KF6HDATMAK6PJ"

# List of items to add to the order with quantity and unit price
items = [
    {"id": "8DYWC6D2S9TD0", "name": "Smoothie", "unit_price": 550, "quantity": 2},
    {"id": "8G6QWTADNZNZP", "name": "Sandwich", "unit_price": 600, "quantity": 3},
    {"id": "A7K2XW2EZ8JN2", "name": "Bagel", "unit_price": 200, "quantity": 1},
    {"id": "GK72D4TSAYKB2", "name": "Croissant", "unit_price": 300, "quantity": 4},
    {"id": "B5B8SS9JH66RR", "name": "Muffin", "unit_price": 250, "quantity": 2},
    {"id": "45B98RBPE4FS2", "name": "Americano", "unit_price": 350, "quantity": 1},
    {"id": "1F36C3CV9HACM", "name": "Mocha", "unit_price": 500, "quantity": 2},
    {"id": "P641AXAHFNBDT", "name": "Cappuccino", "unit_price": 450, "quantity": 1},
    {"id": "0RC507W7JPPRT", "name": "Espresso", "unit_price": 300, "quantity": 3},
    {"id": "YVXGPJV4BFSX8", "name": "Latte", "unit_price": 400, "quantity": 2}
]

# API endpoint for adding items to the order
url = f"https://sandbox.dev.clover.com/v3/merchants/{merchant_id}/orders/{order_id}/line_items"
headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

# Iterate over the items and add each to the order with quantity and unit price
for item in items[:3]:
    total_price = item["unit_price"] * item["quantity"]  # Calculate total price
    payload = {
        "item": {"id": item["id"]},
        "name": item["name"],
        "price": item["unit_price"],  # This is the unit price in Clover
        "quantity": item["quantity"],  # Adding quantity to the order
        "total": total_price  # Optional: calculating total on your end
    }
    
    response = requests.post(url, json=payload, headers=headers)
    
    if response.status_code == 200:
        print(f"Added {item['quantity']}x {item['name']} (Unit price: {item['unit_price']}, Total: {total_price})")
    else:
        print(f"Failed to add item: {item['name']} - {response.text}")
