control 'SV-55430' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan actions for handling File Reputation lookup detections must be set to Quarantine Risk as first action.'
  desc 'This setting is required for the weekly scan parameter Security Risks First Action policy. When a security risk is detected, the first action to be performed must be the option to quarantine the risk.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Insight Lookup tab, Malicious files -> Ensure First action is set to "Quarantine Risk".

Criteria: If First action is not set to "Quarantine Risk", this is a finding.

On the client machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}\\Malware\\TCID-18
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}\\Malware\\TCID-18

Criteria:  If the value of FirstAction is not 1, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Insight Lookup tab, Malicious files -> Set First action to "Quarantine Risk".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48966r3_chk'
  tag severity: 'medium'
  tag gid: 'V-42702'
  tag rid: 'SV-55430r1_rule'
  tag stig_id: 'DTASEP047'
  tag gtitle: 'DTASEP047'
  tag fix_id: 'F-48287r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
