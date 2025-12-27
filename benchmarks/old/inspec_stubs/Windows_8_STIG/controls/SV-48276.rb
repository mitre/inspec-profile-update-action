control 'SV-48276' do
  title 'Users with Administrative privilege must have separate accounts for administrative duties and normal operational tasks.'
  desc 'Using a privileged account to perform routine functions makes the computer vulnerable to malicious software inadvertently introduced during a session that has been granted full privileges.'
  desc 'check', 'Verify each user with administrative privileges has been assigned a unique administrative account separate from their standard user account.

The ISSO will maintain a list of all users belonging to the Administrators group.

If any of the following conditions are true, this is a finding:

-Each SA does not have a unique userid dedicated for administering the system.
-Each SA does not have a separate account for normal user tasks.'
  desc 'fix', 'Ensure each user with administrative privilege has a separate account for user duties and one for privileged duties.'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44954r4_chk'
  tag severity: 'high'
  tag gid: 'V-36659'
  tag rid: 'SV-48276r3_rule'
  tag stig_id: 'WN08-00-000005-02'
  tag gtitle: 'WIN00-000005-02'
  tag fix_id: 'F-41411r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
