# Step 1: Clone the repository
cd /path/to/new/location
#git clone https://github.com/your-username/your-repository.git
git clone git@github.com:karthikarun1/ml_model_deployment_tool.git

# Step 2: Switch to the development branch
cd your-repository
git checkout development
git pull origin development

# Step 3: Create the tag and new branch
git tag -a v1.0 -m "Release version 1.0"
git push origin v1.0
git checkout -b release-branch-name
git push origin release-branch-name
