control 'SV-257772' do
  title 'The macOS system must prevent nonprivileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing nonprivileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Nonprivileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from nonprivileged users.'
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
  tag check_id: 'C-61513r922848_chk'
  tag severity: 'medium'
  tag gid: 'V-257772'
  tag rid: 'SV-257772r922850_rule'
  tag stig_id: 'APPL-12-002069'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-61437r922849_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
