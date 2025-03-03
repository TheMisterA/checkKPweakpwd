# KeePass Weak Password Checker
This Python script checks the strength of passwords stored in a KeePass database and identifies weak passwords. It uses the PyKeePass library to interact with the KeePass database and the zxcvbn library to evaluate password strength.

# Features
Loads a KeePass database and iterates through all entries.
Checks the strength of each password using the zxcvbn library.
Identifies and lists weak passwords (default : score less than 3).
Exports the results to a text file.

# Prerequisites
Python 3.x
pykeepass library
zxcvbn library
You can install the required libraries using pip:

pip install pykeepass zxcvbn
Usage
Define the path to your KeePass database and the password:

Update the db_path and password variables in the script with the appropriate values.
Run the script:

# Execute the script to check the strength of the passwords in your KeePass database.
from pykeepass import PyKeePass
from zxcvbn import zxcvbn

# Define the path to the KeePass database and the password
Be careful! This is for one-time use! Otherwise, secure via call vault or other methods
db_path = '[path]/[DB].kdbx'
password = '[password]'

try:
    # Load the KeePass database
    kp = PyKeePass(db_path, password=password)
except Exception as e:
    print(f"Error loading KeePass database: {e}")
    exit(1)

# List to store the results
results = []
weak_password_count = 0  # Counter for weak passwords

# Retrieve the full path of an entry
def get_entry_path(entry):
    if hasattr(entry.group, "path"):  # Check if the attribute exists
        return " / ".join(entry.group.path)
    return "Root"  # If no group, it's the root

# Iterate through all entries and check the strength of the passwords
for entry in kp.entries:
    try:
        if entry.password:
            result = zxcvbn(entry.password)
            if result['score'] < 3:  # Score from 0 to 4, where 0 is very weak and 4 is very strong
                entry_path = get_entry_path(entry)  # Retrieve the full path
                results.append(f"Path: {entry_path}\nEntry Title: {entry.title}\nPassword: {entry.password}\nScore: {result['score']}\n")
                weak_password_count += 1  # Increment the counter
    except Exception as e:
        print(f"Error processing entry {entry.title if hasattr(entry, 'title') else 'Unknown'}: {e}")

# Define the path to the output file
output_path = '[path]/weak_passwords.txt'

# Content of the file
file_content = [
    "Here is the list of weak passwords in the KeePass database\n",
    f"Total number of weak passwords: {weak_password_count}\n",
    "\n".join(results) if results else "No weak passwords detected."
]

# Export the results to a text file
try:
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(file_content))
    print(f"The results have been exported to the file {output_path}.")
except Exception as e:
    print(f"Error writing to the file: {e}")
Review the output:
The script will generate a text file containing the list of weak passwords and their details.
Security Considerations
Ensure that the db_path and password variables are not hard-coded in the script when sharing it. Use environment variables or a secure vault to manage these sensitive details.
Avoid including actual passwords in the output file. Consider only listing the paths and scores of weak passwords.
License
This project is licensed under the MIT License. See the LICENSE file for details.

Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.
