#args: model_filename=${1:-"sample_model.pkl"}
#args: version=${2:-"v0"}
#args: description="${3:-"Description for model $model_filename and version ${version}"}"
#args: accuracy=${4:-0.5}
#args: model_name=${5:-"sample_model"}
#
#
set -x
./upload_curl_jwt_test.sh abcdef sample_model.pkl v1 "Description for sample_model v1" 100 sample_model
#./upload_curl_jwt_test.sh random_forest_model.pkl v1 "Description for random_forest_model v1" 100 random_forest_model
#./upload_curl_jwt_test.sh sample_model.pkl v2 "Description for sample_model v2" 99 abcdef
