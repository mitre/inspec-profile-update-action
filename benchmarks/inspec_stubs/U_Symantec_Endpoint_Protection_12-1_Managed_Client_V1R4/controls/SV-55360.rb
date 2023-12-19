control 'SV-55360' do
  title 'The Symantec Endpoint Protection client Auto-Protect File Types options must be configured to scan all files.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring antivirus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console: Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology, select Auto-Protect -> Select the Scan Details tab -> Under Scanning, File types -> Ensure "Scan all files" is selected.

Criteria:  If "Scan all files" is not selected, this is a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow632Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan

Criteria:  If the value of FileType is not 0, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology, select Auto-Protect -> Select the Scan Items tab -> Under Scanning, File types -> Select "Scan all files".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48903r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42632'
  tag rid: 'SV-55360r1_rule'
  tag stig_id: 'DTASEP012'
  tag gtitle: 'DTASEP012'
  tag fix_id: 'F-48216r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
