control 'SV-95633' do
  title 'AAA Services must be configured to allow the use of a temporary password at initial logon with an immediate change to a permanent password.'
  desc 'Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial logon. 

Temporary passwords are typically used to allow access to applications when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts that allow the users to log on, yet force them to change the password once they have successfully authenticated.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.

Where passwords are used, such as temporary or emergency accounts, verify AAA Services are configured to allow the use of a temporary password at initial logon with an immediate change to a permanent password. This requirement may be verified by demonstration or configuration review. 

If AAA Services are not configured to allow the use of a temporary password at initial logon with an immediate change to a permanent password, this is a finding.'
  desc 'fix', 'Configure AAA Services to allow the use of a temporary password at initial logon with an immediate change to a permanent password. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80661r2_chk'
  tag severity: 'medium'
  tag gid: 'V-80923'
  tag rid: 'SV-95633r1_rule'
  tag stig_id: 'SRG-APP-000397-AAA-000560'
  tag gtitle: 'SRG-APP-000397-AAA-000560'
  tag fix_id: 'F-87779r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
