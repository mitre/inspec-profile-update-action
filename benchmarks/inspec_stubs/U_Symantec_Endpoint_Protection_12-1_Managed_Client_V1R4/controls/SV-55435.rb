control 'SV-55435' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan must be configured for scanning load points.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring antivirus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans ->Double-click the Weekly Scan -> Under the Scan Details tab -> Ensure "Common infection locations" is selected.

Criteria:  If "Common infection locations" is not selected, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}

Criteria:  If the value of ScanLoadPoints is not 1, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Scan Details tab -> Select "Common infection locations".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48979r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42707'
  tag rid: 'SV-55435r1_rule'
  tag stig_id: 'DTASEP053'
  tag gtitle: 'DTASEP053'
  tag fix_id: 'F-48293r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
