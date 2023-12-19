control 'SV-55510' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan actions for handling File Reputation lookup detections must be set to Leave alone (log only) if first action fails.'
  desc 'This setting is required for the weekly scan parameter Security Risks First action policy. When a Security Risk is detected, if the first action fails the second option must be set to leave alone (log only).'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Under Scan Options -> Select Insight Lookup -> Under Specify actions for reputation detection -> Ensure If first action fails is set to "Leave alone (log only)".

Criteria:  If first action fails is not set to "Leave alone (log only)", this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}\\Malware\\TCID-18
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}\\Malware\\TCID-18

Criteria:  If the value of SecondAction is not 4, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Under Scan Options -> Select Insight Lookup -> Under Specify actions for reputation detection -> Set if first action fails to "Leave alone (log only)".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49054r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42782'
  tag rid: 'SV-55510r2_rule'
  tag stig_id: 'DTASEP048'
  tag gtitle: 'DTASEP048'
  tag fix_id: 'F-48368r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
