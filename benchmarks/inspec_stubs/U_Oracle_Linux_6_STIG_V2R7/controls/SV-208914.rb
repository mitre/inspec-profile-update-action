control 'SV-208914' do
  title 'The rsh-server package must not be installed.'
  desc %q(The "rsh-server" package provides several obsolete and insecure network services. Removing it decreases the risk of those services' accidental (or intentional) activation.)
  desc 'check', 'Run the following command to determine if the "rsh-server" package is installed: 

# rpm -q rsh-server

If the package is installed, this is a finding.'
  desc 'fix', 'The "rsh-server" package can be uninstalled with the following command: 

# yum erase rsh-server'
  impact 0.7
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9167r357722_chk'
  tag severity: 'high'
  tag gid: 'V-208914'
  tag rid: 'SV-208914r793700_rule'
  tag stig_id: 'OL6-00-000213'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-9167r357723_fix'
  tag 'documentable'
  tag legacy: ['SV-64761', 'V-50555']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
