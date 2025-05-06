control 'SV-217982' do
  title 'The xinetd service must be uninstalled if no network services utilizing it are enabled.'
  desc %q(Removing the "xinetd" package decreases the risk of the xinetd service's accidental (or intentional) activation.)
  desc 'check', 'If network services are using the xinetd service, this is not applicable.

Run the following command to determine if the "xinetd" package is installed: 

# rpm -q xinetd


If the package is installed, this is a finding.'
  desc 'fix', 'The "xinetd" package can be uninstalled with the following command: 

# yum erase xinetd'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19463r376961_chk'
  tag severity: 'low'
  tag gid: 'V-217982'
  tag rid: 'SV-217982r603264_rule'
  tag stig_id: 'RHEL-06-000204'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-19461r376962_fix'
  tag 'documentable'
  tag legacy: ['V-38584', 'SV-50385']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
