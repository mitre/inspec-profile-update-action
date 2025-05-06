control 'SV-248716' do
  title 'OL 8 must not allow blank or null passwords in the password-auth file.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', 'To verify that null passwords cannot be used, run the following command:

$ sudo grep -i nullok /etc/pam.d/password-auth

If output is produced, this is a finding.'
  desc 'fix', 'Remove any instances of the "nullok" option in the "/etc/pam.d/password-auth" file to prevent logons with empty passwords.

Note: Manual changes to the listed file may be overwritten by the "authselect" program.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52150r779712_chk'
  tag severity: 'high'
  tag gid: 'V-248716'
  tag rid: 'SV-248716r779714_rule'
  tag stig_id: 'OL08-00-020332'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52104r779713_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
