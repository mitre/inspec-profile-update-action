control 'SV-55434' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan must be configured to prevent users from stopping a scheduled scan.'
  desc 'Antivirus software is the mostly commonly used technical control for malware threat mitigation. Antivirus software on hosts should be configured to scan all hard drives regularly to identify any file system infections and to scan any removable media, if applicable, before media is inserted into the system. Not scheduling a regular scan of the hard drives of a system and/or not configuring the scan to scan all files and running processes introduces, a higher risk of threats going undetected.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Advanced, Scan Progress Options -> Ensure "Allow the user to stop a scan" is NOT selected.

Criteria:  If "Allow the user to stop a scan" is selected, this is a finding.

Client Check:  There is no way to properly validate on the client side. It must be performed on the server.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Advanced, Scan Progress Options -> Ensure "Allow the user to stop a scan" is NOT selected.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48978r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42706'
  tag rid: 'SV-55434r1_rule'
  tag stig_id: 'DTASEP052'
  tag gtitle: 'DTASEP052'
  tag fix_id: 'F-48292r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
