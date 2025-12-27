control 'SV-257223' do
  title 'The macOS system must authenticate peripherals before establishing a connection.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.'
  desc 'check', 'Verify the macOS system is configured to require authentication to access all system-level preference panes with the following commands:

/usr/bin/sudo /usr/bin/security authorizationdb read system.preferences | /usr/bin/grep -A1 shared

<key>shared</key>
<false/>

If the "shared" key is not set to "false", this is a finding.'
  desc 'fix', 'Configure the macOS system to require authentication to access all system-level preference panes with the following actions:

Copy the authorization database to a file:
/usr/bin/sudo /usr/bin/security authorizationdb read system.preferences > ~/Desktop/authdb.txt

Edit the "shared" section of the file:
     <key>shared</key>
    <false/>

Reload the authorization database:
/usr/bin/sudo /usr/bin/security authorizationdb write system.preferences < ~/Desktop/authdb.txt'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60908r905300_chk'
  tag severity: 'medium'
  tag gid: 'V-257223'
  tag rid: 'SV-257223r905302_rule'
  tag stig_id: 'APPL-13-002069'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag fix_id: 'F-60849r905301_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
