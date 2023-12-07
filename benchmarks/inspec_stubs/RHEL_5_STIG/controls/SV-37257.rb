control 'SV-37257' do
  title 'The /etc/sysctl.conf file must be group-owned by root.'
  desc "The sysctl.conf file specifies the values for kernel parameters to be set on boot.  These settings can affect the system's security."
  desc 'fix', 'Use the chgrp command to change the group owner of /etc/sysctl.conf to root:
# chgrp root /etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-4335'
  tag rid: 'SV-37257r1_rule'
  tag stig_id: 'GEN000000-LNX00500'
  tag gtitle: 'GEN000000-LNX00500'
  tag fix_id: 'F-31203r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
