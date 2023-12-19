control 'SV-218019' do
  title 'The qpidd service must not be running.'
  desc 'The qpidd service is automatically installed when the "base" package selection is selected during installation. The qpidd service listens for network connections which increases the attack surface of the system. If the system is not intended to receive AMQP traffic then the "qpidd" service is not needed and should be disabled or removed.'
  desc 'check', 'To check that the "qpidd" service is disabled in system boot configuration, run the following command: 

# chkconfig "qpidd" --list

Output should indicate the "qpidd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "qpidd" --list
"qpidd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "qpidd" is disabled through current runtime configuration: 

# service qpidd status

If the service is disabled the command will return the following output: 

qpidd is stopped


If the service is running, this is a finding.'
  desc 'fix', 'The "qpidd" service provides high speed, secure, guaranteed delivery services. It is an implementation of the Advanced Message Queuing Protocol. By default the qpidd service will bind to port 5672 and listen for connection attempts. The "qpidd" service can be disabled with the following commands: 

# chkconfig qpidd off
# service qpidd stop'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19500r377072_chk'
  tag severity: 'low'
  tag gid: 'V-218019'
  tag rid: 'SV-218019r603264_rule'
  tag stig_id: 'RHEL-06-000267'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-19498r377073_fix'
  tag 'documentable'
  tag legacy: ['SV-50449', 'V-38648']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
