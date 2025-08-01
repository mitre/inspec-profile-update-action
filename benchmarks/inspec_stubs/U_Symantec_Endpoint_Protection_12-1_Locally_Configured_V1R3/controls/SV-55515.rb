control 'SV-55515' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan must be configured for scanning well-known viruses and security risks.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring antivirus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Under Scan Options -> Under Scan Enhancements -> Ensure "Well-known virus and security risk locations", is selected.

Criteria:  If "Well-known virus and security risk locations" is not selected, this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}

Criteria:  If the value of ScanERASERDefs is not 1, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Under Scan Enhancements -> Select "Well-known virus and security risk locations".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49059r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42787'
  tag rid: 'SV-55515r2_rule'
  tag stig_id: 'DTASEP054'
  tag gtitle: 'DTASEP054'
  tag fix_id: 'F-48373r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
