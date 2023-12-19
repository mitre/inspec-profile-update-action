control 'SV-55504' do
  title 'The Symantec Endpoint Protection client Auto-Protect Scan Actions for Security Risks must be configured to Quarantine Risk if first action fails.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the antivirus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option to ensure the malware is not introduced onto the system or network.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Auto-Protect tab -> Select Actions ->  Select Security Risks -> Ensure If first action fails is set to "Quarantine Risk". 

Criteria:  If first action fails is not set to "Quarantine Risk", this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key:
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan\\Expanded
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan\\Expanded

Criteria:  If the value of "SecondAction" is not 1, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Auto-Protect tab -> Select Actions ->  Select Security Risks -> Set if first action fails to "Quarantine Risk".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49048r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42776'
  tag rid: 'SV-55504r1_rule'
  tag stig_id: 'DTASEP042'
  tag gtitle: 'DTASEP042'
  tag fix_id: 'F-48362r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
