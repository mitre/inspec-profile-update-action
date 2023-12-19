control 'SV-208918' do
  title 'The ypbind service must not be running.'
  desc 'Disabling the "ypbind" service ensures the system is not acting as a client in a NIS or NIS+ domain.'
  desc 'check', 'To check that the "ypbind" service is disabled in system boot configuration, run the following command: 

# chkconfig "ypbind" --list

Output should indicate the "ypbind" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "ypbind" --list
"ypbind" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "ypbind" is disabled through current runtime configuration: 

# service ypbind status

If the service is disabled the command will return the following output: 

ypbind is stopped

If the service is running, this is a finding.'
  desc 'fix', 'The "ypbind" service, which allows the system to act as a client in a NIS or NIS+ domain, should be disabled. The "ypbind" service can be disabled with the following commands: 

# chkconfig ypbind off
# service ypbind stop'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9171r357734_chk'
  tag severity: 'medium'
  tag gid: 'V-208918'
  tag rid: 'SV-208918r603263_rule'
  tag stig_id: 'OL6-00-000221'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-9171r357735_fix'
  tag 'documentable'
  tag legacy: ['V-50565', 'SV-64771']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
