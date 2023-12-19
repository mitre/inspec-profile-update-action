control 'SV-80465' do
  title 'Trend Deep Security must alert the ISSO, ISSM, and other designated personnel (deemed appropriate by the local organization) when the unauthorized installation of software is detected.'
  desc 'Unauthorized software not only increases risk by increasing the number of potential vulnerabilities, it also can contain malicious code. Sending an alert (in real time) when unauthorized software is detected allows designated personnel to take action on the installation of unauthorized software.

This requirement applies to configuration management applications or similar types of applications designed to manage system processes and configurations (e.g., HBSS and software wrappers).'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure the ISSO, ISSM, and other designated personnel (deemed appropriate by the local organization) are alerted when the unauthorized installation of software is detected.

1. Analyze the system using the Administration >> System Settings >> Alerts tab. Review the email address listed in the “Alert Event Forwarding (From The Manager).” 

If this email address is not present or does not belong to a distribution for system administrators and ISSOs, this is a finding.

2. Analyze the system using the Administration >> System Settings >> System Events for “Software Added” Event ID 151.

If the options for “Record” and “Forward” are not enabled for “Software Added”, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to alert the ISSO, ISSM, and other designated personnel (deemed appropriate by the local organization) when the unauthorized installation of software is detected.

1. Configure Events and Alerts to notify the SA and ISSO using the Administration >> System Settings >> Alerts tab. Inset a distribution email address into the “Alert Event Forwarding (From The Manager).” The distribution email address must be configured within Exchange or other email server and must associate the SA and ISSO accounts reviewing and/or managing the system.

2. Configure the alert using the Administration >> System Settings >> System Events for “Software Added” Event ID 151. Select the options for “Record” and “Forward”.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66623r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65975'
  tag rid: 'SV-80465r1_rule'
  tag stig_id: 'TMDS-00-000280'
  tag gtitle: 'SRG-APP-000377'
  tag fix_id: 'F-72051r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001811']
  tag nist: ['CM-11 (1)']
end
