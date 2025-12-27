control 'SV-208912' do
  title 'The xinetd service must be uninstalled if no network services utilizing it are enabled.'
  desc %q(Removing the "xinetd" package decreases the risk of the xinetd service's accidental (or intentional) activation.)
  desc 'check', 'If network services are using the xinetd service, this is not applicable.

Run the following command to determine if the "xinetd" package is installed: 

# rpm -q xinetd

If the package is installed, this is a finding.'
  desc 'fix', 'The "xinetd" package can be uninstalled with the following command: 

# yum erase xinetd'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9165r357716_chk'
  tag severity: 'low'
  tag gid: 'V-208912'
  tag rid: 'SV-208912r793698_rule'
  tag stig_id: 'OL6-00-000204'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-9165r357717_fix'
  tag 'documentable'
  tag legacy: ['SV-64755', 'V-50549']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
