control 'SV-248714' do
  title 'OL 8 must not allow accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', 'To verify that null passwords cannot be used, run the following command:
 
$ sudo grep -i permitemptypasswords /etc/ssh/sshd_config 
 
PermitEmptyPasswords no 
 
If "PermitEmptyPasswords" is set to "yes", this is a finding.'
  desc 'fix', 'Edit the following line in "etc/ssh/sshd_config" to prevent logons with empty passwords. 
 
PermitEmptyPasswords no 
 
The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command: 
 
$ sudo systemctl restart sshd.service'
  impact 0.7
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52148r779706_chk'
  tag severity: 'high'
  tag gid: 'V-248714'
  tag rid: 'SV-248714r779708_rule'
  tag stig_id: 'OL08-00-020330'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52102r779707_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
