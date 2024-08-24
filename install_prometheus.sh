# Download the Prometheus tarball
wget https://github.com/prometheus/prometheus/releases/download/v2.42.1/prometheus-2.42.1.linux-amd64.tar.gz

# Extract the tarball
tar xvf prometheus-2.42.1.linux-amd64.tar.gz

# Move into the Prometheus directory
cd prometheus-2.42.1.linux-amd64

# Run Prometheus
./prometheus --config.file=prometheus.yml
