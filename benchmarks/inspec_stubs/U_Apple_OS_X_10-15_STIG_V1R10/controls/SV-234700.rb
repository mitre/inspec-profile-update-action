control 'SV-234700' do
  title 'The macOS system must authenticate peripherals before establishing a connection.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.'
  desc 'check', 'To check that macOS is configured to require authentication to all system preference panes, use the following commands:

/usr/bin/sudo /usr/bin/security authorizationdb read system.preferences | grep -A1 shared

If what is returned does not include the following, this is a finding.
      <key>shared</key>
      <false/>'
  desc 'fix', 'To ensure that authentication is required to access all system level preference panes use the following procedure:

Copy the authorization database to a file using the following command:
/usr/bin/sudo /usr/bin/security authorizationdb read system.preferences > ~/Desktop/authdb.txt

Edit the file to change:
<key>shared</key>
<true/>

To read:
<key>shared</key>
<false/>

Reload the authorization database with the following command:
/usr/bin/sudo /usr/bin/security authorizationdb write system.preferences < ~/Desktop/authdb.txt'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-37884r855798_chk'
  tag severity: 'medium'
  tag gid: 'V-234700'
  tag rid: 'SV-234700r855799_rule'
  tag stig_id: 'AOSX-15-002069'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag fix_id: 'F-26889r855799_fix'
  tag 'documentable'
  tag legacy: ['SV-111785', 'V-102823']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
