control 'SV-220001' do
  title 'The system must restrict the ability of users to assume excessive privileges to members of a defined group and prevent unauthorized users from accessing administrative tools.'
  desc 'Allowing any user to elevate their privileges can allow them excessive control of the system tools.'
  desc 'check', %q(Verify the root user is configured as a role, rather than a normal user. 

# userattr type root

If the command does not return the word "role", this is a finding.

Verify at least one local user has been assigned the root role.

# grep '[:;]roles=root[^;]*' /etc/user_attr

If no lines are returned, or no users are permitted to assume the root role, this is a finding.)
  desc 'fix', "The root role is required.

Convert the root user into a role. 

# usermod -K type=role root

Add the root role to authorized users' logins. 

# usermod -R +root [username]

Remove the root role from users who should not be authorized to assume it.

# usermod -R -root [username]"
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-21711r372694_chk'
  tag severity: 'medium'
  tag gid: 'V-220001'
  tag rid: 'SV-220001r603268_rule'
  tag stig_id: 'SOL-11.1-040200'
  tag gtitle: 'SRG-OS-000324'
  tag fix_id: 'F-21710r372695_fix'
  tag 'documentable'
  tag legacy: ['V-48055', 'SV-60927']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
