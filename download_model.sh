name=$1
version=$2
token=$3
set -x
curl -X GET http://localhost:5000/download_model/$name/$version \
-H "Authorization: Bearer $token" -o /tmp/tmp.pkl
