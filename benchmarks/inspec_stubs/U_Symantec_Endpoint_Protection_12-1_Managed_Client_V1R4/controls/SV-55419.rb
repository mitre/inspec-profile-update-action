control 'SV-55419' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan must be configured to scan all file types or to scan excluded files option must be documented with, and approved by, IAO/IAM.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring antivirus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Scan Details tab, Scanning -> Ensure "Scan all files" is selected, or If "Scan Only Selected Extensions:" is selected -> Select Extensions -> Ensure any selected extensions are documented and approved by the IAO/IAM.
 
Criteria:  If "Scan all files" is not selected, or If "Scan Only Selected Extensions" is selected and the extensions are not documented with, and approved by, the IAO/IAM, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}
64 bit: 
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}

Criteria:  If the value of FileType is not 1, or If the value of "ExcludeByExtension", "HaveExceptionDirs", "HaveExceptionFiles" are 1, and the IAO/IAM has approved the use of exclusions, this is not a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Scan Details tab, Scanning -> Select "Scan all files", or  If "Scan Only Selected Extensions:" is selected -> Select Extensions -> Ensure any selected extensions are documented with, and approved by, the IAO/IAM.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48962r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42691'
  tag rid: 'SV-55419r1_rule'
  tag stig_id: 'DTASEP045'
  tag gtitle: 'DTASEP045'
  tag fix_id: 'F-48276r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
