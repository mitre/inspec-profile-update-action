control 'SV-55530' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan actions for when a Security Risk has been detected must be configured to Delete risk as first action.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the antivirus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option to ensure the malware does is not introduced onto the system or network.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Select Actions -> Select Security Risk -> Ensure first action is set to "Delete Risk".

Criteria:  If first action is not set to "Delete Risk", this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}\\Expanded
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}\\Expanded

Criteria:  If the value of "FirstAction" is not 3, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Select Actions -> Select Security Risk -> Set first action to "Delete Risk".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49074r3_chk'
  tag severity: 'medium'
  tag gid: 'V-42802'
  tag rid: 'SV-55530r2_rule'
  tag stig_id: 'DTASEP069'
  tag gtitle: 'DTASEP069'
  tag fix_id: 'F-48388r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
