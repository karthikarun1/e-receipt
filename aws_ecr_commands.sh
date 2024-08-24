
AWS_ACCOUNT_ID="145023114031"
REGION="us-east-2"

# Authenticate Docker to ECR:
# Run the following command to authenticate Docker to your ECR repository (replace <region> with your AWS region):
echo "aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"


# Tag Your Docker Image:

# Tag your Docker image for ECR (replace <aws_account_id>, <region>, and my-model-deployment-tool with your details):

echo "docker tag my-model-deployment-tool:latest ${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/my-model-deployment-tool:latest"

# Push to remote ECR repo
echo "docker push <aws_account_id>.dkr.ecr.<region>.amazonaws.com/my-model-deployment-tool:latest"
