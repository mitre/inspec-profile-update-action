control 'SV-208929' do
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
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9182r357767_chk'
  tag severity: 'low'
  tag gid: 'V-208929'
  tag rid: 'SV-208929r793715_rule'
  tag stig_id: 'OL6-00-000246'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9182r357768_fix'
  tag 'documentable'
  tag legacy: ['SV-65015', 'V-50809']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
