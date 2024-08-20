# Create local instance of s3
pip install localstack
localstack start  # starts s3 at http://localhost:4566

# create local s3 bucket
aws s3api create-bucket --bucket my-bucket --endpoint-url http://localhost:4566 --region us-east-1

# Run a local instance of dynamodb using docker
docker run -d -p 8000:8000 amazon/dynamodb-local

# create table in local dynamodb
aws dynamodb create-table --cli-connect-timeout 0 \
  --endpoint-url http://localhost:8000 \
  --table-name MyTable \
  --attribute-definitions AttributeName=id,AttributeType=S \
  --key-schema AttributeName=id,KeyType=HASH \
  --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5

aws dynamodb create-table     --table-name MyTable     --attribute-definitions AttributeName=id,AttributeType=S     --key-schema AttributeName=id,KeyType=HASH     --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5     --endpoint-url http://localhost:8000


# list dynamodb tables
aws dynamodb list-tables --endpoint-url http://localhost:8000

# Get detailed information about a specific table
aws dynamodb describe-table --table-name MyTable --endpoint-url http://localhost:8000

# delete dynamodb table
aws dynamodb delete-table --table-name MyTable --endpoint-url http://localhost:8000

# Re-create the table with 'id' as attribute key
aws dynamodb create-table \
    --table-name MyTable \
    --attribute-definitions AttributeName=id,AttributeType=S \
    --key-schema AttributeName=id,KeyType=HASH \
    --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
    --endpoint-url http://localhost:8000

# List s3 buckets
aws s3api list-buckets --endpoint-url http://localhost:4566
# get bucket location
aws s3api get-bucket-location --bucket my-bucket --endpoint-url http://localhost:4566
