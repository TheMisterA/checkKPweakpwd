from pykeepass import PyKeePass
from zxcvbn import zxcvbn

# Define the path to the KeePass database and the password
# For one-time use! Otherwise, secure via call vault or other methods
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
