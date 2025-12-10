import os
import string

src_dir = "[Insert Config]"

def split_cred(cred):
    credential = cred.strip()
    if ':' in credential:
        email, password = credential.split(':', 1)
    elif ';' in credential:
        email, password = credential.split(';', 1)

    return password


def create_password_files(dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    
    # Dictionary to store file handles for each character type
    file_handles = {}
    
    try:
        for dirpath, _, filenames in os.walk(src_dir):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                with open(file_path, 'r', encoding="latin-1") as file:
                    credentials = file.readlines()
                
                for credential in credentials:
                    password = split_cred(credential)

                    if not password:
                        continue

                    first_char = password[0].lower()
                    
                    # Determine the output file name
                    if first_char in string.ascii_lowercase:
                        output_file = f"{first_char}_passwords.txt"
                    elif first_char in string.digits:
                        output_file = f"{first_char}_passwords.txt"
                    else:
                        output_file = "symbols_passwords.txt"
                    
                    # Open file handle if not already open
                    if output_file not in file_handles:
                        file_handles[output_file] = open(
                            os.path.join(dest_dir, output_file), 
                            'w', 
                            encoding="latin-1"
                        )
                    
                    # Write credential to appropriate file
                    file_handles[output_file].write(f"{credential}")
    
    finally:
        # Close all file handles
        for handle in file_handles.values():
            handle.close()

            

def sort_password_files_by_password(dest_dir):
    # Walk through the destination directory to find all password files
    for dirpath, _, filenames in os.walk(dest_dir):
        for filename in filenames:
            # Process only files ending with '_passwords.txt'
            if filename.endswith("_passwords.txt"):
                file_path = os.path.join(dirpath, filename)

                # Read all lines (credentials) from the file
                with open(file_path, 'r', encoding="latin-1") as file:
                    credentials = file.readlines()

                # Split the credentials into (username, password) tuples and sort by password
                credentials = [line.strip().split(':', 1) for line in credentials if ':' in line]
                credentials.sort(key=lambda x: x[1])  # Sort by the password part (x[1])

                # Recombine and overwrite the file with sorted credentials
                with open(file_path, 'w', encoding="latin-1") as file:
                    for username, password in credentials:
                        file.write(f"{username}:{password}\n")

    print("All password files have been sorted by passwords.")

if __name__ == "__main__":
    # Specify the destination directory containing the organized password files
    destination_directory = "../results/OrganizedPasswords"

    # add all passwords to their own files
    create_password_files(destination_directory)

    # Sort all passwords in each file alphabetically by the password
    sort_password_files_by_password(destination_directory)

    print(f"All password files in {destination_directory} have been sorted by passwords.")
