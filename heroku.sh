set -e
set -x
docker build -t ml-model-deployment-tool-ak:latest .
heroku container:push web --app ml-model-deployment-tool-ak
heroku container:release web --app ml-model-deployment-tool-ak
