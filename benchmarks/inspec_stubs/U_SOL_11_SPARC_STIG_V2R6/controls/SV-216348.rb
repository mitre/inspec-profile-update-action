control 'SV-216348' do
  title 'Access to a domain console via telnet must be restricted to the local host.'
  desc 'Telnet is an insecure protocol.'
  desc 'check', 'This action applies only to the control domain. 

Determine the domain that you are currently securing.

# virtinfo 
Domain role: LDoms control I/O service root
The current domain is the control domain, which is also an I/O domain, the service domain, and a root I/O domain.

If the current domain is not the control domain, this check does not apply.

Determine if vnsd is in use.

# svcs vntsd
STATE          STIME    FMRI
online         Oct_08   svc:/ldoms/vntsd:default

If the state is not "online", this is not applicable.

Determine if a role has been created for domain console access.

# cat /etc/user_attr | grep solaris.vntsd.consoles
rolename::::type=role;auths=solaris.vntsd.consoles;profiles=All;roleauth=role

If a role for "vntsd.consoles" is not established, this is a finding.'
  desc 'fix', 'The root role is required. This action applies only to the control domain. 

Determine the domain that you are currently securing.

# virtinfo 
Domain role: LDoms control I/O service root
The current domain is the control domain, which is also an I/O domain, the service domain, and a root I/O domain.

If the current domain is not the control domain, this action does not apply.

Create a password-controlled role that has the solaris.vntsd.consoles authorization, which permits access to all domain consoles.

# roleadd -A solaris.vntsd.consoles [role-name]
# passwd [role-name]

Assign the new role to a user.
# usermod -R [role-name] [username]'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17584r371132_chk'
  tag severity: 'medium'
  tag gid: 'V-216348'
  tag rid: 'SV-216348r603267_rule'
  tag stig_id: 'SOL-11.1-040315'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17582r371133_fix'
  tag 'documentable'
  tag legacy: ['V-71495', 'SV-86119']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
