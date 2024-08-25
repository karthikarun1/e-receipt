name="${1}"
version="${2}"
token="${3}"
curl -X DELETE http://localhost:5000/remove_model/$name/$version -H "Authorization: Bearer ${token}"
