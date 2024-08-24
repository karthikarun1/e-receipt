import boto3

# Local DynamoDB
dynamodb = boto3.resource(
    'dynamodb',
    endpoint_url='http://localhost:8000'
)

# Example of creating a table in local DynamoDB
def create_table():
    dynamodb.create_table(
        TableName='MyTable',
        KeySchema=[
            {'AttributeName': 'Id', 'KeyType': 'HASH'}
        ],
        AttributeDefinitions=[
            {'AttributeName': 'Id', 'AttributeType': 'S'}
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )

create_table()
