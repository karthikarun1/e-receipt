source get_token.sh
curl -X POST http://localhost:5000/logout -H "Authorization: Bearer ${token}"
