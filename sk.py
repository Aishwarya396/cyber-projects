import os
import json

# Function to scan extension manifest file for permissions
def scan_manifest(manifest_path):
    with open(manifest_path, 'r') as manifest_file:
        manifest_data = json.load(manifest_file)
        permissions = manifest_data.get('permissions', [])
    return permissions

# Function to scan extension code for potentially malicious behavior
def scan_extension_code(extension_path):
    malicious_flags = []
    for root, dirs, files in os.walk(extension_path):
        for file in files:
            file_path = os.path.join(root, file)
            # Check for potentially malicious behavior
            with open(file_path, 'r', encoding="utf-8") as f:
                content = f.read()
                if "chrome.tabs.executeScript" in content:
                    malicious_flags.append("Extension uses chrome.tabs.executeScript")
                if "localStorage" in content:
                    malicious_flags.append("Extension uses localStorage")
                if "document.createElement('script')" in content:
                    malicious_flags.append("Extension dynamically creates script elements")
            # Add more checks as needed
    return malicious_flags

# Function to generate a report
def generate_report(permissions, malicious_flags):
    report = "Extension Security Scan Report:\n\n"
    report += "Permissions requested by the extension:\n"
    report += '\n'.join(permissions) + '\n\n'
    
    if malicious_flags:
        report += "Potentially malicious behavior detected:\n"
        report += '\n'.join(malicious_flags) + '\n'
    else:
        report += "No potentially malicious behavior detected.\n"
        
    return report

# Function to list JSON files in extension directory
def list_extension_files(extension_dir):
    print("Available JSON files in the extension directory:")
    json_files = [file for file in os.listdir(extension_dir) if file.endswith('.json')]
    for index, json_file in enumerate(json_files, start=1):
        print(f"{index}. {json_file}")
    return json_files

# Main function
def main():
    # Example path to the extension directory
    extension_dir = 'extension/'

    # List JSON files in the extension directory
    json_files = list_extension_files(extension_dir)
    
    if not json_files:
        print("No JSON files found in the extension directory.")
        return

    # Prompt user to choose a JSON file
    file_index = int(input("Enter the number corresponding to the JSON file you want to scan: ")) - 1
    
    if file_index < 0 or file_index >= len(json_files):
        print("Invalid selection. Please enter a valid number.")
        return
    
    selected_json_file = json_files[file_index]
    json_file_path = os.path.join(extension_dir, selected_json_file)

    # Scan manifest file for permissions
    permissions = scan_manifest(json_file_path)

    # Scan extension code for potentially malicious behavior
    malicious_flags = scan_extension_code(extension_dir)

    # Generate report
    scan_report = generate_report(permissions, malicious_flags)
    print(scan_report)

if __name__ == "__main__":
    main()
