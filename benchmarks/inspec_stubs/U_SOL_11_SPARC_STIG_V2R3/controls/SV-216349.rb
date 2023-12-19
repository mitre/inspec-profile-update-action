control 'SV-216349' do
  title 'Access to a logical domain console must be restricted to authorized users.'
  desc 'A logical domain is a discrete, logical grouping with its own operating system, resources, and identity within a single computer system.  Access to the logical domain console provides system-level access to the OBP of the domain.'
  desc 'check', 'The root role is required. This action applies only to the control domain. 

Determine the domain that you are currently securing.

# virtinfo 
Domain role: LDoms control I/O service root
The current domain is the control domain, which is also an I/O domain, the service domain, and a root I/O domain.

If the current domain is not the control domain, this check does not apply.

Determine if the vntsd service is online.

# pfexec svcs vntsd

If the service is not "online", this is not applicable.

Check the status of the vntsd authorization property.

# svcprop -p vntsd/authorization vntsd

If the state is not true, this is a finding.'
  desc 'fix', 'The root role is required. This action applies only to the control domain. 

Determine the domain that you are currently securing.

# virtinfo 
Domain role: LDoms control I/O service root
The current domain is the control domain, which is also an I/O domain, the service domain, and a root I/O domain.

If the current domain is not the control domain, this action does not apply.

Configure the vntsd service to require authorization.

# svccfg -s vntsd setprop vntsd/authorization = true

The vntsd service must be restarted for the changes to take effect.

# svcadm restart vntsd'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17585r371135_chk'
  tag severity: 'medium'
  tag gid: 'V-216349'
  tag rid: 'SV-216349r603267_rule'
  tag stig_id: 'SOL-11.1-040316'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17583r371136_fix'
  tag 'documentable'
  tag legacy: ['SV-86121', 'V-71497']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
