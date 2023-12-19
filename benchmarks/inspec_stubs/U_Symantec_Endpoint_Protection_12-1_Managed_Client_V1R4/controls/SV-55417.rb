control 'SV-55417' do
  title 'The Symantec Endpoint Protection client scheduled weekly scan must be configured to scan memory.'
  desc 'Antivirus software is the most commonly used technical control for malware threat mitigation. Antivirus software on hosts should be configured to scan all hard drives regularly to identify any file system infections. Not scheduling a regular scan of the hard drives of a system and/or not configuring the scan to scan all files introduces, a higher risk of threats going undetected.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Scan Details tab, Scanning -> Ensure "Memory" is selected. 

Criteria:  If "Memory" is not selected, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}
64 bit: 
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}

Criteria : If the value of ScanProcesses is not 1, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Scan Details tab, Scanning -> Select "Memory".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48960r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42689'
  tag rid: 'SV-55417r1_rule'
  tag stig_id: 'DTASEP044'
  tag gtitle: 'DTASEP044'
  tag fix_id: 'F-48274r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
