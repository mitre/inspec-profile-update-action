control 'SV-80747' do
  title 'The HP FlexFabric Switch must allow the use of a temporary password for system logons with an immediate change to a permanent password.'
  desc 'Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial logon.

Temporary passwords are typically used to allow access to applications when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts that allow the users to log on yet force them to change the password once they have successfully authenticated.'
  desc 'check', 'Determine if the HP FlexFabric Switch allows the use of a temporary password for system logons with an immediate change to a permanent password.  This requirement may be verified by demonstration, configuration review, or validated test results. This requirement may be met through use of a properly configured authentication server if the device is configured to use the authentication server.

[HP] display password-control

Global password control configurations:
 Password control:                    Enabled

If the use of a temporary password for system logons with an immediate change to a permanent password is not allowed, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to allow the use of a temporary password for system logons with an immediate change to a permanent password.

[HP] password-control enable

Note: Once password control feature is enabled, user is forced to change password upon next logon.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66903r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66257'
  tag rid: 'SV-80747r1_rule'
  tag stig_id: 'HFFS-ND-000113'
  tag gtitle: 'SRG-APP-000397-NDM-000312'
  tag fix_id: 'F-72333r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
