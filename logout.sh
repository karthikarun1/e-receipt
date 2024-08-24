token="${1}"
curl -X POST http://localhost:5000/logout -H "Authorization: Bearer ${token}"
