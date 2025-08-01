control 'SV-55408' do
  title 'The Symantec Endpoint Protection client Auto-Protect Advanced Options Automatic enablement setting must be enabled.'
  desc "For antivirus software to be effective, it must be running at all times, beginning from the point of the system's initial startup. Otherwise, the risk is greater for viruses, Trojans, and other malware infecting the system during that startup phase."
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Auto-Protect tab -> Select Advanced -> Under Automatic enablement -> Ensure "When Auto-Protect is disabled, enable after" is selected -> Ensure time limit is set to 5 minutes or less. 

Criteria:  If "When Auto-Protect is disabled, enable after" is not selected, this is a finding. 
If "When Auto-Protect is disabled, enable after" is selected and the time limit is not set to 5 minutes or less, this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key:
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan

Criteria:  If the value of APEOn is not 1 and the value of APESleep is not <= 5, this is a finding. If
APESleep is > 5 or APEOn is not 1, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Auto-Protect tab -> Select Advanced -> Under Automatic enablement ->  Select "When Auto-Protect is disabled, enable after" -> Set the time limit to 5 minutes or less.'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-48951r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42680'
  tag rid: 'SV-55408r1_rule'
  tag stig_id: 'DTASEP016'
  tag gtitle: 'DTASEP016'
  tag fix_id: 'F-48265r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
