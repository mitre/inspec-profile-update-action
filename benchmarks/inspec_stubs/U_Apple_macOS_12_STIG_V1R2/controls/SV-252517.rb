control 'SV-252517' do
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
edit the file to change:
    <key>shared</key>
    <true/>
To read:
    <key>shared</key>
    <false/>

Reload the authorization database with the following command:
/usr/bin/sudo /usr/bin/security authorizationdb write system.preferences < ~/Desktop/authdb.txt'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55973r816363_chk'
  tag severity: 'medium'
  tag gid: 'V-252517'
  tag rid: 'SV-252517r816479_rule'
  tag stig_id: 'APPL-12-002069'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag fix_id: 'F-55923r816478_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
