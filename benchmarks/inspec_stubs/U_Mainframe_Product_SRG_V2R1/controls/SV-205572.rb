control 'SV-205572' do
  title 'The Mainframe Product must allow the use of a temporary password for system logons with an immediate change to a permanent password.'
  desc 'Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial logon. 

Temporary passwords are typically used to allow access to applications when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts that allow the users to log on, yet force them to change the password once they have successfully authenticated.'
  desc 'check', 'If the mainframe product uses an external security manager for all account management functions, this is not applicable.

Examine Mainframe Product account management settings.

If the Mainframe Product account management settings do not allow for the use of a temporary password for system logons with an immediate change to a permanent password, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to allow the use of a temporary password for system logons with an immediate change to a permanent password.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5838r299943_chk'
  tag severity: 'medium'
  tag gid: 'V-205572'
  tag rid: 'SV-205572r851338_rule'
  tag stig_id: 'SRG-APP-000397-MFP-000238'
  tag gtitle: 'SRG-APP-000397'
  tag fix_id: 'F-5838r299944_fix'
  tag 'documentable'
  tag legacy: ['SV-82885', 'V-68395']
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
