control 'SV-91667' do
  title 'The DBN-6300 must enforce 24 hours/1 day as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement.

Restricting this setting limits the user's ability to change their password. Passwords need to be changed at specific policy-based intervals; however, if the network device allows the user to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'To see if the system requires a minimum password lifetime attempt to change your password two times quickly. 

If the user is able to change their password the second time, this is a finding.'
  desc 'fix', 'Set the password-minAge variable within the DBN-6300 through the CLI.

This value is set with the following registry entry in the CLI:
reg set /sysconfig/auth/01 {"stores": {"local": {"policies": {"passwordReuse": {"check": true, "minAge": 3600 }}}}}'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76597r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76971'
  tag rid: 'SV-91667r1_rule'
  tag stig_id: 'DBNW-DM-000064'
  tag gtitle: 'SRG-APP-000173-NDM-000260'
  tag fix_id: 'F-83667r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
