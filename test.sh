rm -f models/*

perform_test() {
  local command="$1"
  local expected_output="$2"

  # Run the command and capture the output
  echo "command is $command"
  local output="$(eval $command)"


  # Perform the assertion
  if [[ "$output" == "$expected_output" ]]; then
    echo "Test passed!"
    return 0
  else
    echo "Test failed!"
    echo "Expected output:"
    echo "$expected_output"
    echo "Actual output:"
    echo "$output"
    exit 1
  fi
}

echo "test: uploading good data"
command="./upload.sh \
	--model_name sample \
	--model_file sample_model.pkl \
	--version v1"
expected_output=$(cat <<EOF
{
  "metadata_path": "models/sample_v1_metadata.json",
  "model_name": "sample",
  "version": "v1"
}
EOF
)
perform_test "$command" "$expected_output"

actual_file="models/sample_v1_metadata.json"
expected_file="/tmp/expected_metadata.json"
# Define the expected content, ignoring dynamic fields
cat <<EOF > "$expected_file"
{
    "model_name": "sample",
    "file_extension": "pkl",
    "version": "v1",
    "description": "No description",
    "accuracy": "N/A",
    "created_by": {
        "username": "admin"
    }
}
EOF
# Extract, sort, and compare relevant parts of the JSON
if jq -S . "$actual_file" | jq 'del(.created_at)' | diff - <(jq -S . "$expected_file"); then
    echo "File contents are as expected."
else
    echo "File contents differ from expected."
    exit 1
fi


# Function to check if a file exists and matches the expected size
check_file() {
    local file=$1
    local expected_size=$2

    if [ -f "$file" ]; then
        actual_size=$(stat -c%s "$file")  # Get the file size in bytes
        if [ "$actual_size" -eq "$expected_size" ]; then
            echo "File '$file' exists and matches the expected size ($expected_size bytes)."
        else
            echo "File '$file' exists but does not match the expected size. Expected $expected_size bytes, got $actual_size bytes."
            exit 1
        fi
    else
        echo "File '$file' does not exist."
        exit 1
    fi
}

# List of files with expected names and sizes (in bytes)
declare -A expected_files=(
    ["models/sample_v1_metadata.json"]="243"  # Filename: Expected size in bytes
    ["models/sample_v1.pkl"]="19079"
)

# Iterate over the expected files and check each one
for file in "${!expected_files[@]}"; do
    check_file "$file" "${expected_files[$file]}"
done

echo "All files exist and match the expected size."

command="./download.sh --model_name sample --version v1"
echo $command
rm -f /tmp/tmp.pkl
eval $command
declare -A expected_files=(
    ["/tmp/tmp.pkl"]="19079"
)
# Iterate over the expected files and check each one
for file in "${!expected_files[@]}"; do
    check_file "$file" "${expected_files[$file]}"
done

command="./predict.sh --model_name sample --version v1"
expected_output=$(cat <<EOF
{
  "prediction": [
    1
  ]
}
EOF
)
perform_test "$command" "$expected_output"


command="./predict.sh --model_name sample --version v1 --expected_output 1"
expected_output=$(cat <<EOF
{
  "accuracy": "True",
  "prediction": [
    1
  ]
}

EOF
)
perform_test "$command" "$expected_output"

command="./predict.sh --model_name sample --version v1 --expected_output 5"
expected_output=$(cat <<EOF
{
  "accuracy": "False",
  "prediction": [
    1
  ]
}

EOF
)
perform_test "$command" "$expected_output"


command="./predict.sh --model_name sample --version v2"
expected_output=$(cat <<EOF
{
  "error": "Not Found",
  "message": "Metadata for model sample version v2 not found"
}
EOF
)
perform_test "$command" "$expected_output"

echo "test: uploading good data"
command="./upload.sh \
	--model_name sample \
	--model_file sample_model.pkl \
	--version v2 \
	--accuracy 0.7"
expected_output=$(cat <<EOF
{
  "metadata_path": "models/sample_v2_metadata.json",
  "model_name": "sample",
  "version": "v2"
}
EOF
)
perform_test "$command" "$expected_output"

echo "test: uploading without version"
command="./upload.sh \
	--model_name forest \
	--model_file random_forest_model.pkl"
expected_output=$(cat <<EOF
{
  "error": "Bad Request",
  "message": "version is required"
}
EOF
)
perform_test "$command" "$expected_output"

echo "test: listing"
command="./list.sh"
expected_output=$(cat <<EOF
{
  "metadata": [
    {
      "file_extension": "json",
      "model_name": "sample_v2"
    },
    {
      "file_extension": "json",
      "model_name": "sample_v1"
    }
  ],
  "v1": [
    {
      "file_extension": "pkl",
      "model_name": "sample"
    }
  ],
  "v2": [
    {
      "file_extension": "pkl",
      "model_name": "sample"
    }
  ]
}
EOF
)
perform_test "$command" "$expected_output"

echo "test: removing existing model good"
command="./remove.sh \
	--model_name sample \
	--version v2"
expected_output=$(cat <<EOF
{
  "message": "Removed model sample_v2.pkl and metadata"
}
EOF
)
perform_test "$command" "$expected_output"

echo "test: listing"
command="./list.sh"
expected_output=$(cat <<EOF
{
  "metadata": [
    {
      "file_extension": "json",
      "model_name": "sample_v1"
    }
  ],
  "v1": [
    {
      "file_extension": "pkl",
      "model_name": "sample"
    }
  ]
}
EOF
)
perform_test "$command" "$expected_output"

echo "test: removing non existing model name"
command="./remove.sh \
	--model_name sample1 \
	--version v2"
expected_output=$(cat <<EOF
{
  "error": "Not Found",
  "message": "Metadata for model sample1 version v2 not found"
}
EOF
)
perform_test "$command" "$expected_output"

echo "test: removing non existing version"
command="./remove.sh \
	--model_name sample \
	--version v3"
expected_output=$(cat <<EOF
{
  "error": "Not Found",
  "message": "Metadata for model sample version v3 not found"
}
EOF
)
perform_test "$command" "$expected_output"

echo "test: removing existing model good"
command="./remove.sh \
	--model_name sample \
	--version v1"
expected_output=$(cat <<EOF
{
  "message": "Removed model sample_v1.pkl and metadata"
}
EOF
)
perform_test "$command" "$expected_output"

echo "test: listing"
command="./list.sh"
expected_output=$(cat <<EOF
{}
EOF
)
perform_test "$command" "$expected_output"

echo "test: uploading good data"
command='./upload.sh --model_name forest --model_file random_forest_model.pkl --description "Random forest model v0" --version v0'
expected_output=$(cat <<EOF
{
  "metadata_path": "models/forest_v0_metadata.json",
  "model_name": "forest",
  "version": "v0"
}
EOF
)
perform_test "$command" "$expected_output"

actual_file="models/forest_v0_metadata.json"
expected_file="/tmp/expected_metadata.json"
# Define the expected content, ignoring dynamic fields
cat <<EOF > "$expected_file"
{
    "model_name": "forest",
    "file_extension": "pkl",
    "version": "v0",
    "description": "Random forest model v0",
    "accuracy": "N/A",
    "created_by": {
        "username": "admin"
    }
}
EOF
# Extract, sort, and compare relevant parts of the JSON
if jq -S . "$actual_file" | jq 'del(.created_at)' | diff - <(jq -S . "$expected_file"); then
    echo "File contents are as expected."
else
    echo "File contents of $actual_file differ from expected $expected_file."
    exit 1
fi

echo "test: listing"
command="./list.sh"
expected_output=$(cat <<EOF
{
  "metadata": [
    {
      "file_extension": "json",
      "model_name": "forest_v0"
    }
  ],
  "v0": [
    {
      "file_extension": "pkl",
      "model_name": "forest"
    }
  ]
}
EOF
)
perform_test "$command" "$expected_output"

command="./download.sh --model_name forest --version v0"
echo $command
eval $command
declare -A expected_files=(
    ["/tmp/tmp.pkl"]="285465"
)
# Iterate over the expected files and check each one
for file in "${!expected_files[@]}"; do
    check_file "$file" "${expected_files[$file]}"
done

echo "test: removing existing model good"
command="./remove.sh \
	--model_name forest \
	--version v0"
expected_output=$(cat <<EOF
{
  "message": "Removed model forest_v0.pkl and metadata"
}
EOF
)
perform_test "$command" "$expected_output"

echo "test: listing"
command="./list.sh"
expected_output=$(cat <<EOF
{}
EOF
)
perform_test "$command" "$expected_output"

command="./download.sh sample v10"
command="./download.sh --model_name not_found --version v10"
echo $command
eval $command
expected_content='{
  "error": "Not Found",
  "message": "Metadata for model not_found version v10 not found"
}'

if diff <(cat /tmp/tmp.pkl) <(echo "$expected_content") > /dev/null; then
    echo "File contents match expected content."
else
    echo "File contents do not match expected content."
    exit 1
fi
