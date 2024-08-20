# stop all running instances of docker
docker stop $(docker ps -q)

# Create the Docker group (if it doesn't exist)
sudo groupadd docker

# Add your user to the Docker group
sudo usermod -aG docker $USER

# Log out and log back in for the changes to take effect
# Alternatively, apply group changes in the current session
newgrp docker

# Verify Docker service is running
sudo systemctl status docker

# Start Docker service if it's not running
sudo systemctl start docker

# Check Docker socket permissions
ls -l /var/run/docker.sock

# Restart Docker service if needed
sudo systemctl restart docker

# After creating the docker-compose.yml file:
docker-compose up --build

# health check
docker inspect --format='{{json .State.Health}}' <container_id>

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
