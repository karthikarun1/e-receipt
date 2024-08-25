import utils

data = {
    "name": "John <script>alert('xss');</script>",
    "details": {
        "age": "25",
        "address": {
            "city": "New <b>York</b>",
            "zipcode": "10001"
        }
    },
    "tags": ["<img src='x'>", "admin"]
}

data = utils.sanitize_input(data)
print (data)
