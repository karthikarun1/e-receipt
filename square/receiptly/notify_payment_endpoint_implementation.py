@app.route('/notify_payment', methods=['POST'])
def notify_payment():
    data = request.json
    payment_id = data.get('payment_id')

    # Step 1: Fetch payment details from Square
    payment_details = fetch_square_payment_details(payment_id)

    # Step 2: Extract card fingerprint
    card_fingerprint = payment_details.get('card_details').get('card').get('fingerprint')

    # Step 3: Check if the customer exists in Receiptly's database
    customer = find_customer_by_fingerprint(card_fingerprint)

    # Step 4: Decide whether to prompt for email/phone
    if not customer:
        # New customer, prompt for email/phone
        return prompt_for_contact_info()
    else:
        # Existing customer, send the receipt
        return send_receipt_to_customer(customer)
