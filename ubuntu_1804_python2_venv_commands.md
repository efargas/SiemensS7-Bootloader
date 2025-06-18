```bash
# 1. Install Python 2.7, pip for Python 2, and python-virtualenv
sudo apt-get update
sudo apt-get install -y python2.7 python-pip python-virtualenv

# 2. Create a directory named project_env
mkdir project_env

# 3. Create a Python 2.7 virtual environment named venv_py2 inside project_env
# On Ubuntu 18.04, python-virtualenv typically installs the 'virtualenv' command.
# We specify the Python 2.7 interpreter.
virtualenv -p python2.7 project_env/venv_py2

# 4. Show the command to activate the virtual environment
echo "To activate the virtual environment, run:"
echo "source project_env/venv_py2/bin/activate"

# 5. Show the command to deactivate the virtual environment
echo "To deactivate the virtual environment (after activation), run:"
echo "deactivate"
```
