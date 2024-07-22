#!/bin/sh

# Loop through each argument in the list and execute corresponding script
for script_path in "$@"; do
    echo "Execute $script_path script"
    bash "$script_path" &
done

# Wait for all background processes to finish
wait

echo "All scripts have finished execution"