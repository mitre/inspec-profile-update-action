control 'SV-233199' do
  title 'The container platform must allow the use of a temporary password for system logons with an immediate change to a permanent password.'
  desc 'Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial login.

Temporary passwords are typically used to allow access to applications when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts, which allow the users to log in, yet forces them to change the password once they have successfully authenticated.'
  desc 'check', 'Review the container platform configuration to determine if the platform is configured to allow the use of a temporary password for system logons with an immediate change to a permanent password. 

If the container platform is not configured to allow temporary passwords with immediate change to a permanent password, this is a finding.'
  desc 'fix', 'Configure the container platform to allow the use of a temporary password for system logons with an immediate change to a permanent password.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36135r601801_chk'
  tag severity: 'medium'
  tag gid: 'V-233199'
  tag rid: 'SV-233199r601802_rule'
  tag stig_id: 'SRG-APP-000397-CTR-000955'
  tag gtitle: 'SRG-APP-000397'
  tag fix_id: 'F-36103r601085_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
