control 'SV-215302' do
  title 'The AIX SSH daemon must be configured to disable empty passwords.'
  desc 'When password authentication is allowed, PermitEmptyPasswords specifies whether the server allows login to accounts with empty password strings. If an account has an empty password, anyone could log in and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', %q(Check the SSH daemon configuration for allowed empty passwords using command: 

# grep -i PermitEmptyPasswords /etc/ssh/sshd_config | grep -v '^#' 
PermitEmptyPasswords no

If no lines are returned, or the returned "PermitEmptyPasswords" directive contains "yes", this is a finding.)
  desc 'fix', 'Edit "/etc/ssh/sshd_config" and add or edit the "PermitEmptyPasswords " line as:
PermitEmptyPasswords  no

Save the change and restart ssh daemon:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16500r294357_chk'
  tag severity: 'medium'
  tag gid: 'V-215302'
  tag rid: 'SV-215302r877377_rule'
  tag stig_id: 'AIX7-00-002120'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-16498r294358_fix'
  tag 'documentable'
  tag legacy: ['V-91743', 'SV-101841']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
