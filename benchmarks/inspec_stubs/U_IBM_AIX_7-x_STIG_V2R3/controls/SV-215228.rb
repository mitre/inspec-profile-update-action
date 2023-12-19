control 'SV-215228' do
  title 'AIX must implement a way to force an identified temporary user to renew their password at next login.'
  desc 'Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial login.

Temporary passwords are typically used to allow access when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts which allow the users to log on, yet force them to change the password once they have successfully authenticated.'
  desc 'check', 'To force a temporary user to renew their password at next login, admins can set the "flags" attribute of the user to contain "ADMCHG" flag.

To check the "flags" attribute for a temporary user (<tmp_user>), using the following command:
# lsuser -a flags <tmp_user>

If the above command displays a "no" value for the "flags" attribute, or the value of the attribute does not contain "ADMCHG", this is a finding.'
  desc 'fix', 'Use the following command to force a temporary user (<tmp_user>) to change password at next login:
# chsec -f /etc/security/passwd -s <tmp_user> -a "flags=ADMCHG"'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16426r294135_chk'
  tag severity: 'medium'
  tag gid: 'V-215228'
  tag rid: 'SV-215228r508663_rule'
  tag stig_id: 'AIX7-00-001131'
  tag gtitle: 'SRG-OS-000380-GPOS-00165'
  tag fix_id: 'F-16424r294136_fix'
  tag 'documentable'
  tag legacy: ['V-91545', 'SV-101643']
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
