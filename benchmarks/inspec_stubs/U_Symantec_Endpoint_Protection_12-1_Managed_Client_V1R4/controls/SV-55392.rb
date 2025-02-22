control 'SV-55392' do
  title 'The Symantec Endpoint Protection client must be configured with a full scan scheduled to run at least weekly.'
  desc 'Antivirus software is the most commonly used technical control for malware threat mitigation. Antivirus software on hosts should be configured to scan all hard drives regularly to identify any file system infections. Not scheduling a regular scan of the hard drives of a system and/or not configuring the scan to scan all files introduces a higher risk of threats going undetected.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Ensure there is at least one full scan enabled that is Weekly or Daily.

Criteria:  If there is no full scan enabled that is Weekly or Daily, this is a finding.

On the client machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{scan ID}\\Schedule
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{scan ID}\\Schedule

Criteria:  If the value of SelectedScanType is not 2, the value of Type is not 1 or 2, and the value of Enabled is not 1, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Create at least one enabled full daily or weekly scan.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48934r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42664'
  tag rid: 'SV-55392r1_rule'
  tag stig_id: 'DTASEP043'
  tag gtitle: 'DTASEP043'
  tag fix_id: 'F-48248r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
