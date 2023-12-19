control 'SV-55356' do
  title 'The Symantec Endpoint Protection client File System Auto-Protect must be enabled.'
  desc "For antivirus software to be effective, it must be running at all times, beginning from the point of the system's initial startup. Otherwise, the risk is greater for viruses, Trojans and other malware infecting the system during that startup phase."
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console: Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology, Select Auto-Protect -> Select the Scan Details tab -> Ensure "Enable Auto-Protect" is selected.                                                

Criteria: If "Enable Auto-Protect" is not selected, this is a finding. 

On the client machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan

Criteria: If the value of APEOff is not 0, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology, select  Auto-Protect -> Select the Scan Details tab -> Select "Enable Auto-Protect".'
  impact 0.7
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48901r1_chk'
  tag severity: 'high'
  tag gid: 'V-42628'
  tag rid: 'SV-55356r1_rule'
  tag stig_id: 'DTASEP010'
  tag gtitle: 'DTASEP010'
  tag fix_id: 'F-48213r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
