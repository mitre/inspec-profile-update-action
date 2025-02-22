control 'SV-55512' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan must be configured to scan compressed files.'
  desc 'Malware is often packaged within compressed files. In addition, compressed files might have other compressed files within. Not scanning compressed files introduces the risk of infected files being introduced into the environment.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Under Scan Options -> Select Advanced -> Under Compressed files options -> Ensure "Scan files inside compressed files", is selected.

Criteria:  If "Scan files inside compressed files" is not selected, this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}

Criteria:  If the value of ZipFile is not 1, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Under Scan Options -> Select Advanced -> Under Compressed files options -> Select "Scan files inside compressed files".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49056r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42784'
  tag rid: 'SV-55512r2_rule'
  tag stig_id: 'DTASEP050'
  tag gtitle: 'DTASEP050'
  tag fix_id: 'F-48370r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
