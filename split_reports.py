import json

input_file = 'full_scan_output.json'
sca_output_file = 'sca_report.json'
sast_output_file = 'sast_report.json'

# Adjusting the input file path to be relative to the current working directory for execution
# The full_scan_output.json would need to be moved or created in the CWD first.
# For now, let's assume it's directly in the CWD or accessible from there.

with open(input_file, 'r') as f:
    data = json.load(f)

sca_report = data.get('sca', {})
sast_report = data.get('sast', {})

with open(sca_output_file, 'w') as f:
    json.dump(sca_report, f, indent=2)

with open(sast_output_file, 'w') as f:
    json.dump(sast_report, f, indent=2)

print(f"SCA report written to {sca_output_file}")
print(f"SAST report written to {sast_output_file}")