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
