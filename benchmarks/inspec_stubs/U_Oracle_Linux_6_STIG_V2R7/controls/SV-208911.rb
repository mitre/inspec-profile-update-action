control 'SV-208911' do
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
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9164r357713_chk'
  tag severity: 'medium'
  tag gid: 'V-208911'
  tag rid: 'SV-208911r793697_rule'
  tag stig_id: 'OL6-00-000203'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-9164r357714_fix'
  tag 'documentable'
  tag legacy: ['SV-64753', 'V-50547']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
