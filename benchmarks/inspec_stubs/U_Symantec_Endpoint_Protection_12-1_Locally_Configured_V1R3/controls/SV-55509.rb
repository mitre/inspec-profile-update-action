control 'SV-55509' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan actions for handling File Reputation lookup detections must be set to Quarantine Risk as first action.'
  desc 'This setting is required for the weekly scan parameter Security Risks First action policy. When a Security Risk is detected, the first action to be performed must be the option to quarantine the risk.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Under Scan Options -> Select Insight Lookup -> Under Specify actions for reputation detection -> Ensure first action is set to "Quarantine Risk".

Criteria:  If First action is not set to "Quarantine Risk", this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}\\Malware\\TCID-18
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}\\Malware\\TCID-18

Criteria:  If the value of FirstAction is not 1, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Under Scan Options -> Select Insight Lookup -> Under Specify actions for reputation detection -> Set first action to "Quarantine Risk".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49053r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42781'
  tag rid: 'SV-55509r2_rule'
  tag stig_id: 'DTASEP047'
  tag gtitle: 'DTASEP047'
  tag fix_id: 'F-48367r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
