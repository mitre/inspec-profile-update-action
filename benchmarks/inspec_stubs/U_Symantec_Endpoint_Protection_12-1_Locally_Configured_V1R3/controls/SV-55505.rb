control 'SV-55505' do
  title 'The Symantec Endpoint Protection client must be configured with a full scan scheduled to run at least weekly.'
  desc 'Antivirus software is the most commonly used technical control for malware threat mitigation. Antivirus software on hosts should be configured to scan all hard drives regularly to identify any file system infections and to scan any removable media, if applicable, before media is inserted into the system. Not scheduling a regular scan of the hard drives of a system and/or not configuring the scan to scan all files introduces a higher risk of threats going undetected.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Under Scans, examine the entries in this list -> Under the When to Scan column -> Ensure there is at least one full scan enabled that is Weekly or Daily.

Criteria:  If there is no full scan enabled that is Weekly or Daily, this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}\\Schedule
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}\\Schedule

Criteria:  If the value of SelectedScanType is not 2, the value of Type is not 1 or 2, and the value of Enabled is not 1, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Under Scans, examine the entries in this list -> Under the When to Scan column -> Create a full scan that is enabled and scheduled to run at least weekly.'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49049r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42777'
  tag rid: 'SV-55505r2_rule'
  tag stig_id: 'DTASEP043'
  tag gtitle: 'DTASEP043'
  tag fix_id: 'F-48363r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
