control 'SV-35069' do
  title 'The inetd.conf file, xinetd.conf file, and the xinetd.d directory must be group-owned by root, bin, sys, or other.'
  desc "Failure to give ownership of sensitive files or utilities to system groups may provide unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'fix', 'Change the group ownership of the inetd configuration file.
# chgrp root <file or directory>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22423'
  tag rid: 'SV-35069r1_rule'
  tag stig_id: 'GEN003730'
  tag gtitle: 'GEN003730'
  tag fix_id: 'F-31884r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
