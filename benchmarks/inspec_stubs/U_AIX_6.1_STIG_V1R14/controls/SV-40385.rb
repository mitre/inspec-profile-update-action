control 'SV-40385' do
  title 'The inetd.conf file, xinetd.conf file, and the xinetd.d directory must be group-owned by bin, sys, or system.'
  desc "Failure to give ownership of sensitive files or utilities to system groups may provide unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of the inetd and xinetd configuration files, and xinetd directory.

Procedure:
# ls -alL /etc/inetd.conf /etc/xinetd.conf /etc/xinetd.d

If a file or directory is not group-owned by bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group ownership of the inetd configuration file.

Procedure:
# chgrp system /etc/inetd.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39250r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22423'
  tag rid: 'SV-40385r1_rule'
  tag stig_id: 'GEN003730'
  tag gtitle: 'GEN003730'
  tag fix_id: 'F-34362r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
