#!/bin/bash
# Installation script for Hopper Scanner

echo "Installing Hopper Scanner dependencies..."

# Check if pip is installed
if ! command -v pip &> /dev/null; then
    echo "Error: pip is not installed. Please install Python and pip first."
    exit 1
fi

# Install required packages
pip install colorama requests

# Verify installation
echo "Verifying installation..."
python -c "import colorama, requests; print('- colorama:', colorama.__version__); print('- requests:', requests.__version__)"

if [ $? -eq 0 ]; then
    echo "Installation successful!"
    echo "You can now run Hopper using: python hopper.py -h"
else
    echo "Error: Installation verification failed. Please check error messages above."
    exit 1
fi

# Make scripts executable
chmod +x hopper.py
if [ -f demo_hopper.sh ]; then
    chmod +x demo_hopper.sh
fi

echo "Done!"