import re
import csv
from collections import defaultdict

# Parse the log file
log_file = 'sample.log'  # Change this to the correct path

ip_addresses = defaultdict(int)
endpoints = defaultdict(int)
failed_logins = defaultdict(int)
suspicious_activity = []

with open(log_file, 'r') as f:
    log_data = f.readlines()

# Regular expression to parse log lines
log_pattern = r'(?P<ip_address>\d+\.\d+\.\d+\.\d+) - - \[.*\] "(?P<method>.*?) (?P<endpoint>.*?) HTTP.*" (?P<status>\d+)'

for entry in log_data:
    match = re.match(log_pattern, entry)
    if match:
        ip_address = match.group('ip_address')
        endpoint = match.group('endpoint')
        status = match.group('status')
        
        # Track IP addresses and endpoints
        ip_addresses[ip_address] += 1
        endpoints[endpoint] += 1
        
        # Track failed login attempts
        if status == '401':
            failed_logins[ip_address] += 1
            if failed_logins[ip_address] > 3:
                suspicious_activity.append(f"Suspicious Activity: IP {ip_address} has {failed_logins[ip_address]} failed login attempts.")

# Display the results
print("Requests per IP Address:")
for ip, count in ip_addresses.items():
    print(f"{ip}      {count}")

# Most Frequently Accessed Endpoint
most_accessed_endpoint = max(endpoints, key=endpoints.get)
print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed_endpoint} (Accessed {endpoints[most_accessed_endpoint]} times)")

# Suspicious Activity Detected
print("\nSuspicious Activity Detected:")
for activity in suspicious_activity:
    print(activity)

# Save results to CSV
with open('log_analysis_results.csv', 'w', newline='') as csvfile:
    fieldnames = ['IP Address', 'Request Count', 'Endpoint', 'Suspicious Activity']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for ip, count in ip_addresses.items():
        writer.writerow({'IP Address': ip, 'Request Count': count, 'Endpoint': '', 'Suspicious Activity': ''})
    for activity in suspicious_activity:
        writer.writerow({'IP Address': '', 'Request Count': '', 'Endpoint': '', 'Suspicious Activity': activity})
