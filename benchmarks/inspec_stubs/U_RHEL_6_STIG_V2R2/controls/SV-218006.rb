control 'SV-218006' do
  title 'The avahi service must be disabled.'
  desc 'Because the Avahi daemon service keeps an open network port, it is subject to network attacks. Its functionality is convenient but is only appropriate if the local network can be trusted.'
  desc 'check', 'To check that the "avahi-daemon" service is disabled in system boot configuration, run the following command: 

# chkconfig "avahi-daemon" --list

Output should indicate the "avahi-daemon" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "avahi-daemon" --list
"avahi-daemon" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "avahi-daemon" is disabled through current runtime configuration: 

# service avahi-daemon status

If the service is disabled the command will return the following output: 

avahi-daemon is stopped


If the service is running, this is a finding.'
  desc 'fix', 'The "avahi-daemon" service can be disabled with the following commands: 

# chkconfig avahi-daemon off
# service avahi-daemon stop'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19487r377033_chk'
  tag severity: 'low'
  tag gid: 'V-218006'
  tag rid: 'SV-218006r603264_rule'
  tag stig_id: 'RHEL-06-000246'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-19485r377034_fix'
  tag 'documentable'
  tag legacy: ['V-38618', 'SV-50419']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
