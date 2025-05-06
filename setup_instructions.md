# Setup Instructions for Hopper Scanner

## Dependencies

Hopper requires the following Python packages:
- Python 3.6 or higher
- colorama (for colored terminal output)
- requests (for HTTP requests)

## Installation

### Method 1: Using pip

```bash
# Install dependencies
pip install colorama requests
```

### Method 2: Using the provided script

On Unix-like systems:
```bash
# Make the installation script executable
chmod +x install.sh

# Run the installation script
./install.sh
```

On Windows:
```
install.bat
```

## Verifying Installation

To verify that Hopper is installed correctly, run:

```bash
python hopper.py -h
```

You should see the Hopper ASCII banner and a list of command-line options.

## Running Demo

To see Hopper in action with a vulnerable test application:

```bash
# Make the demo script executable
chmod +x demo_hopper.sh

# Run the demo
./demo_hopper.sh
```

This will start a local vulnerable application and run several test scans against it.

## Additional Resources

- For custom payloads, see the example in `custom_payloads.txt`
- For a vulnerable test application, see `demo_vulnerable_app.py`