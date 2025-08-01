control 'SV-55507' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan must be configured to scan all file types or scan exclude files option must be documented with, and approved by, IAO/IAM.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring antivirus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Under Scan Options, File Types -> Ensure "All types", or if "Selected Extensions:" is selected -> Select Extensions -> Ensure any selected extensions are documented with, and approved by, the IAO/IAM, is selected.

Criteria:  If "All types", is not selected, or if "Selected Extensions" is selected and the extensions are not documented with, and approved by, the IAO/IAM, this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key:
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}
64 bit: 
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}

Criteria:  If the value of FileType is not 1, or if the value of "ExcludeByExtension", "HaveExceptionDirs", "HaveExceptionFiles" are 1, and the IAO/IAM has approved the use of exclusions, this is not a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Under Scan Options, File Types -> Select "All types", or if "Selected Extensions:" is selected -> Select Extensions -> Ensure any selected extensions are documented with, and approved by, the IAO/IAM, is selected.'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49051r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42779'
  tag rid: 'SV-55507r2_rule'
  tag stig_id: 'DTASEP045'
  tag gtitle: 'DTASEP045'
  tag fix_id: 'F-48365r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
