control 'SV-55394' do
  title 'The Symantec Endpoint Protection client User-defined Exceptions option must not be configured to exclude any files from scanning unless exclusions have been documented with, and approved by, the IAO/IAM.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring antivirus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'On the machine, locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen -> Select "Change Settings" on the left side of the screen -> Select "Configure Settings" for Exceptions -> Ensure there are not any User-defined Exceptions listed that are not documented with, and approved by, the IAO/IAM. 

Criteria:  If any User-defined Exceptions are listed and not documented with, and approved by, the IAO/IAM, this is a finding.'
  desc 'fix', 'On the client machine, locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen -> Select "Change Settings" on the left side of the screen -> Select "Configure Settings" for Exceptions. Remove any User-defined Exceptions that are not documented with, and approved by, the IAO/IAM.'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-48937r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42666'
  tag rid: 'SV-55394r1_rule'
  tag stig_id: 'DTASEP002'
  tag gtitle: 'DTASEP002'
  tag fix_id: 'F-48251r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
