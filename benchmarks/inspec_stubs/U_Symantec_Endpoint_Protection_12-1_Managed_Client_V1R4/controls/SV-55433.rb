control 'SV-55433' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan must be configured to scan compressed files.'
  desc 'Malware is often packaged within compressed files. In addition, compressed files might have other compressed files within. Not scanning compressed files introduces the risk of infected files being introduced into the environment.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click on the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click on Weekly Scan -> Under the Scan Details tab, Scanning, Enhance the scan by checking -> Select Advanced Scanning Options -> Under the Compressed Files, Scanning Compressed Files -> Ensure "Scan files inside compressed files" is selected.

Criteria:  If "Scan files inside compressed files" is not selected, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}

Criteria:  If the value of ZipFile is not 1, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Scan Details tab, Scanning, Enhance the scan by checking -> Select Advanced Scanning Options -> under the Compressed Files, Scanning Compressed Files -> Select "Scan files inside compressed files".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48976r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42705'
  tag rid: 'SV-55433r1_rule'
  tag stig_id: 'DTASEP050'
  tag gtitle: 'DTASEP050'
  tag fix_id: 'F-48290r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
