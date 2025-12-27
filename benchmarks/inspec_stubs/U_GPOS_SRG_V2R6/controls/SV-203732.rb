control 'SV-203732' do
  title 'The operating system must allow the use of a temporary password for system logons with an immediate change to a permanent password.'
  desc 'Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial logon.

Temporary passwords are typically used to allow access when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts which allow the users to log on, yet force them to change the password once they have successfully authenticated.'
  desc 'check', 'Verify the operating system allows the use of a temporary password for system logons with an immediate change to a permanent password. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to allow the use of a temporary password for system logons with an immediate change to a permanent password.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3857r375260_chk'
  tag severity: 'medium'
  tag gid: 'V-203732'
  tag rid: 'SV-203732r851803_rule'
  tag stig_id: 'SRG-OS-000380-GPOS-00165'
  tag gtitle: 'SRG-OS-000380'
  tag fix_id: 'F-3857r375261_fix'
  tag 'documentable'
  tag legacy: ['V-56803', 'SV-71063']
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
