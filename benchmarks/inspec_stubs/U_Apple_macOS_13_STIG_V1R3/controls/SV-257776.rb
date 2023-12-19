control 'SV-257776' do
  title 'The macOS system must prevent nonprivileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing nonprivileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Nonprivileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from nonprivileged users.'
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
  tag check_id: 'C-61517r922881_chk'
  tag severity: 'medium'
  tag gid: 'V-257776'
  tag rid: 'SV-257776r922883_rule'
  tag stig_id: 'APPL-13-002069'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-61441r922882_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
