import csv
import re

# Define a regular expression pattern to match the version numbers
version_pattern = re.compile(r'^(\d+)(\.(\d+))?(\.(\d+))?(-([A-Za-z0-9_-]+))?$')


# Define a function that will convert the version string into a tuple of integers
def version_key(version):
    print(version)
    match = version_pattern.match(version)
    major = int(match.group(1))
    minor = int(match.group(3)) if match.group(3) else 0
    patch = int(match.group(5)) if match.group(5) else 0
    build = match.group(7) if match.group(7) else ''
    return (major, minor, patch, build)
# Define the path to the input CSV file
input_path = 'test3.csv'

# Define the path to the output CSV file
output_path = 'test3sorted.csv'

# Read the input CSV file into a list of dictionaries
with open(input_path, 'r', newline='') as input_file:
    reader = csv.DictReader(input_file)
    values = list(reader)

print(2785+86)

# Sort the values by version number
sorted_values = sorted(values, key=lambda x: version_key(x['version']))

# Write the sorted values to the output CSV file
with open(output_path, 'w', newline='') as output_file:
    fieldnames = ['version', 'number']
    writer = csv.DictWriter(output_file, fieldnames=fieldnames)
    writer.writeheader()
    for value in sorted_values:
        writer.writerow(value)