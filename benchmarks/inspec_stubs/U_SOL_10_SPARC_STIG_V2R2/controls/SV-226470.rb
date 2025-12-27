control 'SV-226470' do
  title 'The system must restrict the ability to switch to the root user to members of a defined group.'
  desc 'Configuring a supplemental group for users permitted to switch to the root user prevents unauthorized users from accessing the root account, even with knowledge of the root credentials.'
  desc 'check', %q(Verify the root user is configured as a role, rather than a normal user.
# egrep '^root:' /etc/user_attr
If the returned line does not include "type=role", this is a finding.

Verify at least one local user has been assigned the root role.
# egrep '[:;]roles=[^;]*,?root([,;]|$)' /etc/user_attr
If no lines are returned, no users are permitted to assume the root role, this is a finding.)
  desc 'fix', "Convert the root user into a role.
# usermod -K type=role root

Add the root role to authorized users' logins.
# usermod -R root <userid>"
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28631r482789_chk'
  tag severity: 'low'
  tag gid: 'V-226470'
  tag rid: 'SV-226470r603265_rule'
  tag stig_id: 'GEN000850'
  tag gtitle: 'SRG-OS-000109'
  tag fix_id: 'F-28619r482790_fix'
  tag 'documentable'
  tag legacy: ['V-22308', 'SV-39876']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
