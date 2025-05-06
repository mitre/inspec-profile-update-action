control 'SV-207485' do
  title 'The VMM must allow the use of a temporary password for system logons with an immediate change to a permanent password.'
  desc 'Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial login. 

Temporary passwords are typically used to allow access when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts which allow the users to log in, yet force them to change the password once they have successfully authenticated.'
  desc 'check', 'Verify the VMM allows the use of a temporary password for system logons with an immediate change to a permanent password.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to allow the use of a temporary password for system logons with an immediate change to a permanent password.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7742r365859_chk'
  tag severity: 'medium'
  tag gid: 'V-207485'
  tag rid: 'SV-207485r854659_rule'
  tag stig_id: 'SRG-OS-000380-VMM-001560'
  tag gtitle: 'SRG-OS-000380'
  tag fix_id: 'F-7742r365860_fix'
  tag 'documentable'
  tag legacy: ['SV-71531', 'V-57271']
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
