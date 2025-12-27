control 'SV-55402' do
  title 'The Symantec Endpoint Protection client File System Auto-Protect must be enabled.'
  desc "For antivirus software to be effective, it must be running at all times, beginning from the point of the system's initial startup. Otherwise, the risk is greater for viruses, Trojans, and other malware infecting the system during that startup phase."
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Auto-Protect tab -> Ensure "Enable File System Auto-Protect" is selected. 

Criteria:  If "Enable File System Auto-Protect" is not selected, this is a finding. 

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan

Criteria:  If the value of APEOff is not 0, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Auto-Protect tab -> Select "Enable File System Auto-Protect".'
  impact 0.7
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-48945r1_chk'
  tag severity: 'high'
  tag gid: 'V-42674'
  tag rid: 'SV-55402r1_rule'
  tag stig_id: 'DTASEP010'
  tag gtitle: 'DTASEP010'
  tag fix_id: 'F-48259r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
