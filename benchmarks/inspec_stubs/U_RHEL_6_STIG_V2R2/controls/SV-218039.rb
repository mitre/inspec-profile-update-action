control 'SV-218039' do
  title 'The netconsole service must be disabled unless required.'
  desc 'The "netconsole" service is not necessary unless there is a need to debug kernel panics, which is not common.'
  desc 'check', 'To check that the "netconsole" service is disabled in system boot configuration, run the following command: 

# chkconfig "netconsole" --list

Output should indicate the "netconsole" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "netconsole" --list
"netconsole" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "netconsole" is disabled through current runtime configuration: 

# service netconsole status

If the service is disabled the command will return the following output: 

netconsole is stopped


If the service is running, this is a finding.'
  desc 'fix', 'The "netconsole" service is responsible for loading the netconsole kernel module, which logs kernel printk messages over UDP to a syslog server. This allows debugging of problems where disk logging fails and serial consoles are impractical. The "netconsole" service can be disabled with the following commands: 

# chkconfig netconsole off
# service netconsole stop'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19520r377132_chk'
  tag severity: 'low'
  tag gid: 'V-218039'
  tag rid: 'SV-218039r603264_rule'
  tag stig_id: 'RHEL-06-000289'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-19518r377133_fix'
  tag 'documentable'
  tag legacy: ['SV-50473', 'V-38672']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
