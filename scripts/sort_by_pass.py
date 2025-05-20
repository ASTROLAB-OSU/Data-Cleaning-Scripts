import os

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
    destination_directory = "OrganizedPasswords"

    # Sort all passwords in each file alphabetically by the password
    sort_password_files_by_password(destination_directory)

    print(f"All password files in {destination_directory} have been sorted by passwords.")
