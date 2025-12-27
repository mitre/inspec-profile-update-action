control 'SV-217985' do
  title 'The rsh-server package must not be installed.'
  desc %q(The "rsh-server" package provides several obsolete and insecure network services. Removing it decreases the risk of those services' accidental (or intentional) activation.)
  desc 'check', 'Run the following command to determine if the "rsh-server" package is installed: 

# rpm -q rsh-server


If the package is installed, this is a finding.'
  desc 'fix', 'The "rsh-server" package can be uninstalled with the following command: 

# yum erase rsh-server'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19466r376970_chk'
  tag severity: 'high'
  tag gid: 'V-217985'
  tag rid: 'SV-217985r603264_rule'
  tag stig_id: 'RHEL-06-000213'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-19464r376971_fix'
  tag 'documentable'
  tag legacy: ['V-38591', 'SV-50392']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
