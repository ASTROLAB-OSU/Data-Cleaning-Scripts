import json
import re

def convert_distribution_file(input_file, output_file):
    distribution_data = {}
    
    # Regular expression to match the expected line format
    pattern = re.compile(
        r"Character:\s*'(?P<char>.)'\s*-\s*Average:\s*(?P<average>[\d.]+)%\s*-\s*Range:\s*\[(?P<min>[\d.]+)%,\s*(?P<max>[\d.]+)%\]"
    )

    with open(input_file, 'r') as infile:
        for line in infile:
            line = line.strip()
            if not line or line.startswith("#"):
                continue  # Skip empty lines or comments

            match = pattern.match(line)
            if match:
                char = match.group("char")
                average = float(match.group("average")) / 100  # Convert percentage to decimal
                min_range = float(match.group("min")) / 100    # Convert percentage to decimal
                max_range = float(match.group("max")) / 100    # Convert percentage to decimal

                # Add to the dictionary
                distribution_data[char] = {
                    "Average": average,
                    "MinRange": min_range,
                    "MaxRange": max_range
                }
            else:
                print(f"Skipping invalid line: {line}")

    # Write the JSON output
    with open(output_file, 'w') as outfile:
        json.dump(distribution_data, outfile, indent=4)

    print(f"Conversion complete. JSON saved to {output_file}")


if __name__ == "__main__":
    # Specify your input and output files
    input_file = "character_distributions.txt"  # Replace with your input file name
    output_file = "char_distributions.json"

    convert_distribution_file(input_file, output_file)
