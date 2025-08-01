control 'SV-217981' do
  title 'The xinetd service must be disabled if no network services utilizing it are enabled.'
  desc 'The xinetd service provides a dedicated listener service for some programs, which is no longer necessary for commonly-used network services. Disabling it ensures that these uncommon services are not running, and also prevents attacks against xinetd itself.'
  desc 'check', 'If network services are using the xinetd service, this is not applicable.

To check that the "xinetd" service is disabled in system boot configuration, run the following command: 

# chkconfig "xinetd" --list

Output should indicate the "xinetd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "xinetd" --list
"xinetd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "xinetd" is disabled through current runtime configuration: 

# service xinetd status

If the service is disabled the command will return the following output: 

xinetd is stopped


If the service is running, this is a finding.'
  desc 'fix', 'The "xinetd" service can be disabled with the following commands: 

# chkconfig xinetd off
# service xinetd stop'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19462r376958_chk'
  tag severity: 'medium'
  tag gid: 'V-217981'
  tag rid: 'SV-217981r603264_rule'
  tag stig_id: 'RHEL-06-000203'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-19460r376959_fix'
  tag 'documentable'
  tag legacy: ['V-38582', 'SV-50383']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
