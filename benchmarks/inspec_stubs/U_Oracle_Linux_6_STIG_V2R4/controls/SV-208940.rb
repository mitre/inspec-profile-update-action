control 'SV-208940' do
  title 'The oddjobd service must not be running.'
  desc 'The "oddjobd" service may provide necessary functionality in some environments but it can be disabled if it is not needed. Execution of tasks by privileged programs, on behalf of unprivileged ones, has traditionally been a source of privilege escalation security issues.'
  desc 'check', 'To check that the "oddjobd" service is disabled in system boot configuration, run the following command: 

# chkconfig "oddjobd" --list

Output should indicate the "oddjobd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "oddjobd" --list
"oddjobd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "oddjobd" is disabled through current runtime configuration: 

# service oddjobd status

If the service is disabled the command will return the following output: 

oddjobd is stopped

If the service is running, this is a finding.'
  desc 'fix', 'The "oddjobd" service exists to provide an interface and access control mechanism through which specified privileged tasks can run tasks for unprivileged client applications. Communication with "oddjobd" is through the system message bus. The "oddjobd" service can be disabled with the following commands: 

# chkconfig oddjobd off
# service oddjobd stop'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9193r357800_chk'
  tag severity: 'low'
  tag gid: 'V-208940'
  tag rid: 'SV-208940r603263_rule'
  tag stig_id: 'OL6-00-000266'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-9193r357801_fix'
  tag 'documentable'
  tag legacy: ['V-50839', 'SV-65045']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
