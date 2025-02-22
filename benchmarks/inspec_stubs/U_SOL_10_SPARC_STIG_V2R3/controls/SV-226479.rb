control 'SV-226479' do
  title 'The root account must not be used for direct logins.'
  desc 'Direct login with the root account prevents individual user accountability. Acceptable non-routine uses of the root account for direct login are limited to emergency maintenance, the use of single-user mode for maintenance, and situations where individual administrator accounts are not available.'
  desc 'check', %q(Check if the root is used for direct logins.

Procedure:
# last root | grep -v reboot

If any direct login records for root exist, this is a finding.

Verify the root user is configured as a role, rather than a normal user.

Procedure:
# egrep '^root:' /etc/user_attr

If the returned line does not include "type=role", this is a finding.)
  desc 'fix', "Convert the root user into a role.
# usermod -K type=role root

Add the root role to authorized users' logins.
# usermod -R root <userid>"
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28640r482822_chk'
  tag severity: 'medium'
  tag gid: 'V-226479'
  tag rid: 'SV-226479r603265_rule'
  tag stig_id: 'GEN001020'
  tag gtitle: 'SRG-OS-000109'
  tag fix_id: 'F-28628r482823_fix'
  tag 'documentable'
  tag legacy: ['V-11979', 'SV-39848']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
