control 'SV-68099' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan must be configured for scanning well-known viruses and security risks.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring antivirus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Scan Details tab, Scanning -> Ensure "Well-known virus and security risk locations" is selected.

Criteria:  If "Well-known virus and security risk locations" is not selected, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Scan Details tab, Scanning -> Select "Well-known virus and security risk locations".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48980r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42708'
  tag rid: 'SV-68099r1_rule'
  tag stig_id: 'DTASEP054'
  tag gtitle: 'DTASEP054'
  tag fix_id: 'F-48294r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
